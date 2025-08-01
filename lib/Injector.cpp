#include "llvm/IR/Constants.h"
#include "llvm/IR/DebugInfoMetadata.h"
#include "llvm/IR/DebugLoc.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/Transforms/Utils/Cloning.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/Error.h"
#include "llvm/Support/raw_ostream.h"

#include <unordered_set>
#include <thread>
#include <sstream>

#include <sys/wait.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "Injector.h"
#include "ModuleAnalysis.h"
#include "FunctionAnalysis.h"
#include "Utils.h"

#include "inject_redis_profile.hpp"

using namespace llvm;

namespace phoenix {

namespace injector {

static void debugPrintInjectIndices(const std::unordered_set<size_t> &inject_insts_idx) {
    lerrs() << "Fault inject index are: [";
    for (auto &idx : inject_insts_idx) {
        lerrs() << idx << ", ";
    }
    lerrs() << "]\n";
}

static void debugPrintToInjectFunction(size_t idx, Function *orig_func, size_t to_count) {
    lerrs() << "Global idx " << idx
        << ", to inject function " << orig_func->getName()
        << ", at subindex " << to_count << '\n';
}

static void debugPrintPrefixSum(const std::vector<std::pair<Function *, size_t>> &func_injectable_count_prefix_sum) {
    lerrs() << "Prefix sum are: [";
    for (auto &[f, idx] : func_injectable_count_prefix_sum) {
        lerrs() << idx << ", ";
    }
    lerrs() << "]\n";
}

static void debugInjectTarget(const Injector::InjectTarget &target) {
    debugPrintInjectIndices(target.inject_insts_idx);
    for (auto &[idx, orig_func, to_count] : target.inject_insts_idx_orig_func) {
        debugPrintToInjectFunction(idx, orig_func, to_count);
    }
    lerrs() << "-phx-inject-offsets=";
    for (auto &[_, orig_func, to_count] : target.inject_insts_idx_orig_func) {
        lerrs() << orig_func->getName() << ":" << to_count << ",";
    }
    lerrs() << '\n';
}

void Injector::checkAndSetOutputFileName() {
    auto output = static_cast<llvm::cl::opt<std::string>*>(
        llvm::cl::getRegisteredOptions().lookup("o"));
    if (!output) {
        die() << "Injector: cannot find output file name option!\n";
    }
    if (output->getValue().rfind(".bc") != output->getValue().size() - 3) {
        die() << "Injector: output file name must end with .bc!\n";
    }
    inject_parallel_output_file_prefix = output->getValue().substr(0, output->getValue().size() - 3);
}

bool Injector::isInjectableFunction(const llvm::Function &f) const {
    if (!isInstrumentableFunction(f))
        return false;

    /* TODO: Make this loadable from a file */
    if (inject_preset == "") {
        return true;
    } else if (inject_preset == "redis") {
        if (inject_func_redis.find(demangleName(f.getName().str())) != inject_func_redis.end()) {
            return true;
        }
        return false;
    } else if (inject_preset == "redis-simple") {
        for (auto &kw : {"list", "dict"}) {
            if (f.getName().contains_insensitive(kw))
                return true;
        }
        return false;
    } else if (inject_preset == "varnish-simple") {
        for (auto &kw : {"obj_", "Obj", "Req_", "hcl_"}) {
            if (f.getName().startswith(kw))
                return true;
        }
        return false;
    } else {
        die() << "Unknown inject preset: " << inject_preset << '\n';
    }

    return true;
}

bool Injector::isToInject(const llvm::Function &f) const {
    for (const auto &[_, orig_func, __] : target.inject_insts_idx_orig_func) {
        if (orig_func == &f) return true;
    }
    return false;
}

void Injector::preprocessPrefixSum(const analysis::TopologyFuncList &sorted_func) {
    lerrs() << "Searching injectable instructions" << '\n';

    /* Calculate the prefix sum of injectable instructions from all functions. */
    total_injectable_count = 0;
    for (auto &[f, order] : sorted_func) {
        size_t this_func_count = 0;

        if (!isInstrumentableFunction(*f))
            continue;

        if (isInjectableFunction(*f)) {
            for (auto &inst : instructions(f)) {
                if (isInjectableInstruction(inst))
                    this_func_count++;
            }
        } else {
            this_func_count = 0;
        }
        // func_injectable_count.push_back(this_func_count);
        total_injectable_count += this_func_count;
        func_injectable_count_prefix_sum.push_back({f, total_injectable_count});
    }
    lerrs() << "Found " << total_injectable_count << " injectable instructions\n";
    lerrs() << "Found " << func_injectable_count_prefix_sum.size() << " injectable functions\n";
    debugPrintPrefixSum(func_injectable_count_prefix_sum);

    if (total_injectable_count == 0) {
        die() << "No injectable instructions available!\n";
    }
}

void Injector::select_injectable_instructions(
    const analysis::TopologyFuncList &sorted_func, size_t select_count,
    const std::vector<std::string> &inject_offsets_override)
{
    if (inject_offsets_override.size() > 0) {
        for (auto &offset : inject_offsets_override) {
            if (offset == "") {
                continue;
            }

            std::stringstream funcname_offset(offset);
            std::string funcname;
            std::getline(funcname_offset, funcname, ':');

            Function *func = getFunctionByName(funcname, M);
            if (!func) {
                die() << "Cannot find injection override function " << funcname << "!\n";
            }

            if (!isInjectableFunction(*func)) {
                lerrs() << "Function " << func->getName() << " not in injection list will be ignored\n";
                continue;
            }

            std::string offset_str;
            std::getline(funcname_offset, offset_str, ':');

            size_t to_count = std::stoul(offset_str);

            // 0 is global idx for debug only
            target.inject_insts_idx_orig_func.push_back({ 0, func, to_count });
        }

        return;
    }

    /* Random select 10 injectable instructions, as global prefix sums.  */
    target.inject_insts_idx = generate_random_set(select_count, 1, total_injectable_count);

    for (auto &idx : target.inject_insts_idx) {

        auto func_idx = std::lower_bound(
                func_injectable_count_prefix_sum.begin(),
                func_injectable_count_prefix_sum.end(), std::make_pair(nullptr, idx),
                [](auto &x, auto &y){ return x.second < y.second; })
            - func_injectable_count_prefix_sum.begin();
        auto orig_func = func_injectable_count_prefix_sum[func_idx].first;
        // lerrs() << "global idx " << idx << " lower_bound is " << func_idx
        //     << ", orig func name: " << orig_func->getName() << '\n';

        // Should not happen anymore.
        //
        // The function 0, and is an external library
        // leaf function.  The lower bound on prefix sum algorithm chooses the
        // first value change in consecutive values, but does not filter first
        // 0 value.
        assert_eq(isInjectableFunction(*orig_func), true);

        // TODO: use absolute offset of the instruction instead of recount injectable?
        size_t to_count = func_idx == 0 ? idx : idx - func_injectable_count_prefix_sum[func_idx - 1].second;

        target.inject_insts_idx_orig_func.push_back({idx, orig_func, to_count});
    }
}

void Injector::collect_injectable_instructions(
    const analysis::ClonedFunctionMap &cloned_function_map)
{
    for (const auto &[_, orig_func, to_count] : target.inject_insts_idx_orig_func) {
        assert_eq(isInjectableFunction(*orig_func), true);

        std::vector<Instruction *> this_inject_insts;

        for (auto &suffix : {injector::OF, injector::IF}) {
            if (cloned_function_map.at(orig_func).find(suffix) == cloned_function_map.at(orig_func).end()) {
                die() << "Injector: suffix " << suffix << " not found in "
                    << orig_func->getName() << '\n';
            }

            auto &inj_func = cloned_function_map.at(orig_func).at(suffix);

            size_t tmp_count = 0;
            for (auto &inst : instructions(inj_func)) {
                if (isInjectableInstruction(inst)) {
                    if (++tmp_count == to_count) {
                        this_inject_insts.push_back(&inst);
                        break;
                    }
                }
            }
            if (tmp_count != to_count) {
                die() << "Injector: exhausted " << orig_func->getName()
                    << ' ' << tmp_count << ' ' << to_count << '\n';
            }
        }
        target.inject_targets.push_back(this_inject_insts);
    }
}

void Injector::inject_all() {
    lerrs() << "About to inject " << target.inject_targets.size() << " faults\n";
    debugInjectTarget(target);
    for (auto &insts : target.inject_targets) {
        for (auto inst : insts) {
            lerrs() << "Injecting at function " << inst->getFunction()->getName() << '\n';

            if (auto MD = inst->getMetadata("dbg")) {
                if (auto *loc = dyn_cast<DILocation>(MD)) {
                    lerrs() << "Line: " << loc->getLine() << " Column: " << loc->getColumn() << '\n';
                }
            }
            injectOneInstruction(inst);

        }
    }
}

void Injector::fork_multiplexer_magic() {
    size_t num_threads = std::thread::hardware_concurrency();
    if (num_threads == 0) {
        num_threads = 1;
    }

    lerrs() << "Injector: Forking processes at " << num_threads << " degrees of parallelism\n";

    for (auto &name : inject_parallel_names) {

        while (child_count >= num_threads) {
            wait(NULL);
            --child_count;
        }

        pid_t pid = fork();
        if (pid == -1) {
            lerrs() << "Failed to fork! Waiting for all children and then abort...\n";
            while (child_count) {
                wait(NULL);
                --child_count;
            }
            exit(1);
        }

        if (pid == 0) {
            // override output file
            std::string outfile = inject_parallel_output_file_prefix + "." + name + ".bc";
            // FIXME: very hacky way to override output file!
            // should scan /proc/self/fd/ and replace specific fd instead.
            int fd = open(outfile.c_str(), O_WRONLY | O_CREAT | O_TRUNC);
            if (fd == -1) {
                die() << "Failed to open output file: " << outfile << '\n';
            }
            dup2(fd, 3);    // 3 is the output bc file descriptor
            close(fd);

            // override log file
            std::string logfile = "inject." + name + ".log";
            std::error_code EC;
            llvm::errs().close();
            new (&llvm::errs()) llvm::raw_fd_ostream(logfile, EC);

            // start child
            return;
        }
        // parent process
        ++child_count;
        lerrs() << "Forked child process " << pid << " for output id " << name << '\n';
    }
}

void Injector::fork_multiplexer_tail() {
    while (child_count) {
        wait(NULL);
        --child_count;
    }
}

void Injector::injectOneInstruction(Instruction *inst) {
    if (auto inst2 = dyn_cast<ICmpInst>(inst)) {
        // inverse comparision method
        lerrs() << "Fault injection: inversed predicate " << *inst << '\n';
        inst2->setPredicate(inst2->getInversePredicate());
    } else if (isa<StoreInst>(inst)) {
        // TODO: currently we only remove the instruction, support more
        // later
        if (0) {
            lerrs() << "Fault injection: removed instruction: " << *inst << '\n';
            inst->eraseFromParent();
        } else {
            lerrs() << "Fault injection: use store null: " << *inst << '\n';

            // Note: cannot directly set operand 1 to null, because the
            // compiler will think it is UB and truncate the function.
            // Therefore, create a global null variable and load it.

            static size_t null_val_count = 0;

            auto gv = new GlobalVariable(*inst->getModule(),
                inst->getOperand(1)->getType(), false,
                GlobalValue::ExternalLinkage,
                Constant::getNullValue(inst->getOperand(1)->getType()),
                "__phx_null_val" + std::to_string(++null_val_count));

            auto b = IRBuilder(inst);
            auto loadinst = b.CreateLoad(gv->getValueType(), gv);
            inst->setOperand(1, loadinst);
            lerrs() << "\tAfter injection:" << *inst << '\n';
        }
    } else if (isa<BinaryOperator>(inst)) {
        lerrs() << "Fault injection: modifying 2nd operand: " << *inst << '\n';
        // llvm::Instruction::BinaryOps::
        if (auto c = dyn_cast<ConstantInt>(inst->getOperand(1))) {
            if (c->isZero()) {
                inst->setOperand(
                    1, ConstantInt::get(inst->getOperand(1)->getType(), 1));
            } else {
                inst->setOperand(
                    1, ConstantInt::get(inst->getOperand(1)->getType(), 0));
            }
        } else {
            // this could be not ConstantInt, e.g. a double
            /* inst->setOperand(
                1, ConstantInt::get(inst->getOperand(1)->getType(), 0)); */
            lerrs() << "Internal Error: Unkown type to be modified" << '\n';
        }
    } else {
        lerrs() << "Internal Error: Unknown instruction to be injected" << '\n';
    }
}





void Injector::select_gen_map_combined() { }

llvm::Function *Injector::get_map(llvm::Function *f, InjectVersion ver) {
    return NULL;
}

void Injector::inject() {

}

} // namespace analysis

} // namespace phoenix
