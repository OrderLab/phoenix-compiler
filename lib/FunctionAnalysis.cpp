#include "llvm/Analysis/TargetLibraryInfo.h"
#include "llvm/IR/Argument.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/InstrTypes.h"
#include "llvm/IR/Instruction.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Operator.h"
#include "llvm/IR/Value.h"
#include "llvm/Pass.h"
#include "llvm/Support/Casting.h"

#include "llvm/BinaryFormat/Dwarf.h"

#include <llvm-15/llvm/IR/DebugInfoMetadata.h>
#include <shared_mutex>
#include <unordered_map>
#include <unordered_set>
#include <queue>

#include "Utils.h"
#include "FieldChain.h"
#include "FunctionAnalysis.h"

using namespace llvm;

namespace phoenix {

namespace analysis {

FunctionSummary FunctionAnalyzer::analyze() {
    FunctionSummary result;

    // FIXME: handle global variable!
    result.argument_effects.push_back(ArgumentEffect{
        ModifyType::NO_MODIFY,
        ReturnTaint::PURE,
        0,
        {},
        {},
    });

    size_t i = 0;
    for (auto &arg : f.args()) {
        dbg_summary() << "=== Analyzing arg " << ++i << '\n';
        result.argument_effects.push_back(analyzeSingleArgument(arg));
        // +1 for global variable
        assert_eq(result.argument_effects.size(), i + 1);
        // +1 for global variable, +1 for 1-based index (variable i)
        assert_eq(result.argument_effects.size(), arg.getArgNo() + 2);
    }

    return result;
}

ArgumentEffect FunctionAnalyzer::analyzeSingleArgument(const Argument &arg) const {
#if 1
    return analyzeArgInsensitive(arg);
#else
    return analyzeArgSensitive(arg);
#endif
}

/*
 * For iterative data flow analysis algorithm, using the block input &
 * output method!
 *
 * When ever a block's output changes, the successors are pushed to this
 * queue.  Use the index of BB in the function to simulate its reverse
 * postorder priority.
 */
struct bbpriority {
    const llvm::BasicBlock *bb;
    int order;
    bool operator<(const bbpriority &rhs) const { return order < rhs.order; }
};
using BBWorkList = std::priority_queue<bbpriority>;
/*
 * This is <instruction or arg (or maybe global?), possible field chain>
 *
 * This also not track StoreInst, even though they do not have "returned value"
 * (i.e. User).  This essentially tracks the memory behind the store.
 * The important thing is that "store" can kill old value, and therefore,
 * flow-sensitive is important.
 *
 * StoreInst that has a "hit" in field chain is also stored in `effect.taints`.
 * Also, calls do get tracked here as they could return some value.
 */
using ValueTrack = std::unordered_map<const Value *, std::vector<FieldChain>>;

struct AnalysisInternal {
    ValueTrack &value_track;
};

#if 0
/* Flow-sensitive analysis */
ArgumentEffect FunctionAnalyzer::analyzeArgSensitive(const Argument &arg) const {

    /* Glossary:
     *   effect.taints: this actually the set of `store` and `call` instructions
     *     ("taint" feels ambiguous, consider change a name)
     *   value_track: formally, the data-flow value. For each Value*, which
     *     fieldchain it contains (could be either modified or not modified).
     *     The iterative analysis terminates on fixpoint of value_track, but
     *     not on a fixpoint of `effect`.
     *   queue: basic block queue to be processed
     */

    BBWorkList worklist;
    analysis::ValueTrack value_track;

    /* A heuristic for the order of work list */
    std::unordered_map<const BasicBlock *, int> bbpriority;

    /* The return value */
    ArgumentEffect effect = {
        ModifyType::NO_MODIFY,
        ReturnTaint::PURE,
        {},
        {},
    };

    value_track[&arg].push_back(nullptr);

    AnalysisInternal internal { .value_track = value_track };

    int pri = f.size();
    for (auto &bb : f) {
        bbpriority[&bb] = pri;
        worklist.push({&bb, pri});
        --pri;
    }

    while (!worklist.empty()) {
        auto [bb, _] = worklist.top();
        worklist.pop();

        bool changed = false;
        for (auto &inst : *bb) {
            changed |= analyzeArgSensitiveProcessUser(effect, internal, &inst);
        }
        if (changed) {
            for (auto outbb : successors(bb)) {
                worklist.push({outbb, bbpriority[outbb]});
            }
        }
    }

    return effect;
}

bool FunctionAnalyzer::analyzeArgSensitiveProcessUser(
        ArgumentEffect &effect, const AnalysisInternal &analysis_internal,
        const Instruction *user) const
{
    ValueTrack &value_track = analysis_internal.value_track;

    // FIXME: this should be all possible chains of the value.
    FieldChain tmpchain(nullptr);

    FieldChain chain = tmpchain;

    auto insertElement = [](const Value *elem, const FieldChain &chain) {
        die() << "Unimplemented!\n";
    };

#define returnTrueIfScoped do {} while (0)

    if (const StoreInst *store = dyn_cast<StoreInst>(user)) {
        /*
        if (elem == store->getValueOperand()) {
            // If it was the src operand, search for definition of dst, add deref
            // to the chain.
            insertElement(store->getPointerOperand(), chain.nest_deref());
        } else {
            if (chain.get() == nullptr)
                effect.taints.insert(user);

            // If it was the dst operand, search for usage of src, remove one
            // deref from chain.
            auto newchain = match_deref(chain);
            if (newchain.hasValue()) {
                if (newchain.getValue().get() == nullptr)
                    returnTrueIfScoped;
                insertElement(store->getValueOperand(), newchain.getValue());
            }
        } */
    } else if (isa<LoadInst>(user)) {
        auto newchain = match_deref(chain);
        if (chain.get() == nullptr)
            insertElement(user, nullptr);
        if (newchain.hasValue()) {
            if (newchain.getValue().get() == nullptr)
                returnTrueIfScoped;
            insertElement(user, newchain.getValue());
        }
    } else if (const GetElementPtrInst *gep = dyn_cast<GetElementPtrInst>(user)) {
        // FIXME: field chain is corrupted
        // dbg() << "current chain: " << chain << '\n';
        bool hit;
        auto newchain = match_gep(chain, gep, &hit);
        if (chain.get() == nullptr) {
            insertElement(user, nullptr);
        }
        else if (hit) {
            // returnTrueIfScoped;
        }
        // addHitPoint(gep, last);
        if (newchain.hasValue())
            insertElement(user, newchain.getValue());
    } else if (isa<ExtractValueInst>(user)) {
        // TODO
        lerrs() << "Unsupported Instruction: " << *user << '\n';
    } else if (isa<InsertValueInst>(user)) {
        // TODO
        lerrs() << "Unsupported Instruction: " << *user << '\n';
    } else if (const CallBase *call = dyn_cast<CallBase>(user)) {
        // if (call->isDebugOrPseudoInst()) continue;

        // FIXME: if indirect, this should get the union of indirect callee(s)
        auto callee = call->getCalledFunction();

        std::shared_lock<std::shared_mutex> guard;
        if (summary_lock)
            guard = std::shared_lock(*summary_lock);
        auto it = summaries.find(callee);
        if (it == summaries.end()) {
            if (callee == call->getCaller()) {
                lerrs() << "Warning: Direct recursion handling TODO!\n";
            } else {
                dbg() << "Warning: Indirect call not handled!\n";
            }
        } else {
            // should get call->getArgOperandNo(&use)
            auto arg_no = INT_MAX;
            // FIXME: change this logic

            // TODO use bitmap as argument taint
            if (it->second.argument_effects.size() == 0) {
                // TODO: changed from loop to this
                return false;
            }
            auto &argeffect = it->second.argument_effects[arg_no];
            if (argeffect.modify_type == ModifyType::MAY_MODIFY) {
                effect.taints.insert(user);
                effect.taint_call_arg[user] = arg_no;
            }
            if (argeffect.return_taint == ReturnTaint::POINTER)
                insertElement(user, nullptr);
        }
    }
    // Constant that may contain global variable
    else if (const Constant *c = dyn_cast<Constant>(user)) {
        // TODO
    }
    else if (const ReturnInst *ret = dyn_cast<ReturnInst>(user)) {
        // TODO: check if returned is a pointer, or recursively has a pointer
        effect.return_taint = ReturnTaint::POINTER;
    } else {
        // lerrs() << "Unknown Instruction: " << *user << '\n';
    }

    return false;
}
#endif

FieldChain getInitArgChain(const Argument &arg, const std::string &phx_preset) {
    const Function *f = arg.getParent();

    DIType *type = nullptr;

    if (auto MD = f->getMetadata("dbg")) {
        auto *subProgram = dyn_cast<DISubprogram>(MD);
        if (!subProgram) return nullptr;

        auto *ftype = subProgram->getType();
        if (!ftype) return nullptr;

        // argidx (0-based) < num ftype->getTypeArray().size() - 1 (-1 to exclude return value)
        if (!(arg.getArgNo() < ftype->getTypeArray().size() - 1)) {
            return nullptr;
        }
        type = ftype->getTypeArray()[arg.getArgNo() + 1];
    }
    if (type == nullptr) return nullptr;

    // TODO: make this a parser
    if (phx_preset == "redis") {
        auto *t1 = dyn_cast<DIDerivedType>(type);
        if (!t1 || t1->getTag() != dwarf::DW_TAG_pointer_type) return nullptr;

        DIType *_t2 = t1->getBaseType();
        if (!_t2) return nullptr;
        auto *t2 = dyn_cast<DIDerivedType>(_t2);
        if (!t2 || t2->getTag() != dwarf::DW_TAG_typedef) return nullptr;

        // typedef struct client
        if (t2->getName() != "client") return nullptr;

        DIType *_t3 = t2->getBaseType();
        if (!_t3) return nullptr;
        auto *t3 = dyn_cast<DICompositeType>(_t3);
        if (!t3 || t3->getTag() != dwarf::DW_TAG_structure_type) return nullptr;

        // struct client
        if (t3->getName() != "client") return nullptr;

        int idx = 0;
        for (const auto &e : t3->getElements()) {
            idx++;

            if (auto *etype = dyn_cast<DIDerivedType>(e)) {
                if (etype->getTag() != dwarf::DW_TAG_member) continue;

                // handle post processing function that contains db info
                if (arg.getParent()->getName().startswith("freeClientArgv")) {
                    if (etype->getName() == "argv") {
                        // -1 because we incremented idx at the beginning of the loop
                        lerrs() << "Found client->argv: " << idx - 1 << '\n';
                        return FieldChain(nullptr).nest_field(nullptr, idx - 1);
                    }
                    continue;
                }

                // regular case, only concern on the db field
                if (etype->getName() == "db") {
                    // -1 because we incremented idx at the beginning of the loop
                    lerrs() << "Found client->db: " << idx - 1 << '\n';
                    return FieldChain(nullptr).nest_field(nullptr, idx - 1);
                }
            }
        }
    }

    return nullptr;
}

static bool inline isPointerHeuristic(const Type *type, const Module *M) {
    if (type->isPointerTy()) return true;
    if (type->isIntegerTy() && type->getIntegerBitWidth() == DataLayout(M).getPointerSizeInBits()) {
        return true;
    }
    return false;
}

/* Flow-insensitive analysis */
ArgumentEffect FunctionAnalyzer::analyzeArgInsensitive(const Argument &arg) const {

    typedef std::queue<std::tuple<const Value *, FieldChain, ssize_t>> VisitQueue;
    typedef std::unordered_map<const Value *, bool> VisitedNodeSet;

    ArgumentEffect effect = {
        ModifyType::NO_MODIFY,
        ReturnTaint::PURE,
        0,
        {},
        {},
    };

    if (isMayModifyExternalSafe(f)) {
        effect.modify_type = ModifyType::MAY_MODIFY_EXTERNAL_SAFE;
        return effect;
    }

    VisitedNodeSet visited;
    VisitQueue queue;

    auto insertElement = [&visited, &queue](const Value *elem, const FieldChain &chain) {
        // hack: filter constant at insert..
        if (isa<Constant>(elem)) return;
        if (visited[elem]) return;
        // lerrs() << "Added: " << *elem << '\n';
        queue.push({elem, chain, 0});
        visited[elem] = true;
    };

    insertElement(&arg, getInitArgChain(arg, phx_preset));

#define returnTrueIfScoped do {} while (0)

    /* The main part is the def-use chain analysis.
     */

    while (!queue.empty()) {
        auto [elem, chain, y] = queue.front();
        queue.pop();

        // dbg() << "=====\n";

        // dbg() << *elem << '\n';

        /* In the comments below, [%x] means where the "use" is, and _%x_ means
         * what should be propagated. */
        for (const Use &use : elem->uses()) {
            const User *user = use.getUser();
            // lerrs() << "processing user " << *user << '\n';

            // TODO: handle global variable
            if (!isa<Instruction>(user) && !isa<ReturnInst>(user)) continue;

            auto user_as_inst = dyn_cast<Instruction>(user);

            if (const StoreInst *store = dyn_cast<StoreInst>(user)) {
                if (elem == store->getValueOperand()) {
                    /* Store value:[%elem], ptr:_%mem_ */

                    // If it was the src operand, search for definition of dst, add deref
                    // to the chain.
                    // TODO: handle global variable
                    if (!isa<Constant>(store->getPointerOperand()))
                        insertElement(store->getPointerOperand(), chain.nest_deref());
                } else {
                    /* Store value:_%value_, ptr:[%elem] */
                    if (chain.get() == nullptr)
                        effect.writes.insert(user_as_inst);

                    // If it was the dst operand, search for usage of src, remove one
                    // deref from chain.
                    auto newchain = match_deref(chain);
                    if (newchain.hasValue()) {
                        if (newchain.getValue().get() == nullptr)
                            returnTrueIfScoped;
                        insertElement(store->getValueOperand(), newchain.getValue());
                    }
                }
            } else if (isa<LoadInst>(user)) {
                /* _%user_ = Load [%elem] */

                auto newchain = match_deref(chain);
                if (chain.get() == nullptr)
                    insertElement(user, nullptr);
                if (newchain.hasValue()) {
                    if (newchain.getValue().get() == nullptr)
                        returnTrueIfScoped;
                    insertElement(user, newchain.getValue());
                }
            } else if (const GetElementPtrInst *gep = dyn_cast<GetElementPtrInst>(user)) {
                /* _%gep_ = GEP [%elem], field idx... */

                if (elem != gep->getPointerOperand()) {
                    // lerrs() << "Debug: elem is not on GEP pointer operand, ignored: " << *gep << "\n";
                    continue;
                }

                // FIXME: field chain is corrupted
                // lerrs() << "current chain: " << chain << '\n';
                bool hit;
                // when GEP is a pointer offset, the newchain will be the same as old chain
                auto newchain = match_gep(chain, gep, &hit);
                // lerrs() << "new chain: " << newchain << " hit " << hit << '\n';
                if (chain.get() == nullptr) {
                    insertElement(user, nullptr);
                }
                else if (hit) {
                    // returnTrueIfScoped;
                    insertElement(gep, nullptr);
                }
                // addHitPoint(gep, last);
                if (newchain.hasValue())
                    insertElement(user, newchain.getValue());
            } else if (isa<ExtractValueInst>(user)
                || isa<InsertValueInst>(user)
                || isa<ShuffleVectorInst>(user)
                || isa<InsertElementInst>(user))
            {
                lerrs() << "Unsupported Instruction: " << *user << '\n';
            } else if (const SelectInst *select = dyn_cast<SelectInst>(user)) {
                if (user == select->getCondition()) {
                    continue;
                }

                if (isPointerHeuristic(select->getType(), f.getParent())) {
                    insertElement(select, chain);
                }
            } else if (isa<BinaryOperator>(user)) {
                auto binop = dyn_cast<BinaryOperator>(user);

                bool pointer_arithmetic_heuristic = false;

                switch (binop->getOpcode()) {
                    case BinaryOperator::Add:
                    case BinaryOperator::Sub:
                        pointer_arithmetic_heuristic = true; break;
                    default: break;
                }

                if (isPointerHeuristic(user->getType(), f.getParent())) {
                    if (pointer_arithmetic_heuristic) {
                        insertElement(user, chain);
                    } else {
                        // lerrs() << "Ignored BinaryOperator: (" << binop->getOpcode() << ") "
                        //  << *user << '\n';
                    }
                }
            } else if (isa<PHINode>(user)
                || isa<IntToPtrInst>(user)
                || isa<PtrToIntInst>(user)
                || isa<FreezeInst>(user))
            {
                if (isPointerHeuristic(user->getType(), f.getParent())) {
                    insertElement(user, chain);
                }
            } else if (isa<BitCastInst>(user)) {
                // basically this is never...
                if (isPointerHeuristic(user->getOperand(0)->getType(), f.getParent())
                    && isPointerHeuristic(user->getType(), f.getParent()))
                {
                    insertElement(user, chain);
                    lerrs() << "Added pointer cast: " << *user << '\n';
                }
            } else if (const AtomicRMWInst *rmw = dyn_cast<AtomicRMWInst>(user)) {
                /*
                 * Atomic instructions are memory writes, follow the store logic
                 */
                if (rmw->getPointerOperand() == user) {
                    if (chain.get() == nullptr)
                        effect.writes.insert(user_as_inst);
                    // TODO: handle match_deref as store logic
                } else if (rmw->getValOperand() == user) {
                    // TODO: handle global variable
                    if (!isa<Constant>(rmw->getPointerOperand()))
                        insertElement(rmw->getPointerOperand(), chain.nest_deref());
                }
                assert(false);
            } else if (const AtomicCmpXchgInst *cas = dyn_cast<AtomicCmpXchgInst>(user)) {
                if (cas->getPointerOperand() == user) {
                    if (chain.get() == nullptr)
                        effect.writes.insert(user_as_inst);
                    // TODO: handle match_deref as store logic
                } else if (cas->getNewValOperand() == user) {
                    // TODO: handle global variable
                    if (!isa<Constant>(cas->getPointerOperand()))
                        insertElement(cas->getPointerOperand(), chain.nest_deref());
                } else if (cas->getCompareOperand() == user) {
                    // TODO: do we still want this?
                }
                assert(false);
            } else if (isa<UnaryOperator>(user)) {
                // actually there is only one unary operator, FNeg in LLVM 15..
                if (user_as_inst->getOpcode() == UnaryOperator::FNeg) {
                    continue;
                }
            } else if (isa<ICmpInst>(user) || isa<FCmpInst>(user)
                || isa<SIToFPInst>(user) || isa<UIToFPInst>(user)
                || isa<FPToSIInst>(user) || isa<FPToUIInst>(user)
                || isa<TruncInst>(user) || isa<FPTruncInst>(user)
                || isa<SExtInst>(user) || isa<ZExtInst>(user) || isa<FPExtInst>(user)
                || isa<SwitchInst>(user))
            {
                /* Do nothing, return value is not a pointer. */
            }
            else if (const CallBase *call = dyn_cast<CallBase>(user)) {
                /* _%callret_ = Call %f, ...[%elem]... __modify_effect_args__ */

                /* Another case:
                 * _%callret_ = Call [%f], ...args... __modify_effect_args__
                 * (TODO, hopefully this is not the case..) */

                // if (call->isDebugOrPseudoInst()) continue;

                assert_eq_custom(call->getCaller(), &f, call->getCaller()->getName(), f.getName());

                auto callee = call->getCalledFunction();

                if (!callee) {
                    dbg() << "Warning: Indirect call not handled!\n";
                    continue;
                } else if (isSelfRecursion(callee)) {
                    // Special: for our unified binary injector, check if the
                    // function was duplicated.
                    lerrs() << "Warning: Direct recursion handling TODO! \n";
                    continue;
                }

                std::shared_lock<std::shared_mutex> guard;
                if (summary_lock) {
                    guard = std::shared_lock(*summary_lock);
                }

                std::optional<FunctionSummary> ext_summary_storage;
                const FunctionSummary *summary = nullptr;

                auto it = summaries.find(callee);
                if (it != summaries.end()) {
                    summary = &it->second;
                }
                else {
                    ext_summary_storage = tryGetExternalFunctionSummary(*callee, phx_preset);
                    if (ext_summary_storage != std::nullopt) {
                        summary = &ext_summary_storage.value();
                    } else {
                        dbg() << "Skipping external function: " << callee->getName() << '\n';
                        continue;
                    }
                }

                auto arg_no = call->getArgOperandNo(&use) + 1;   // +1 for global variable

                /* Update callsite instruction taint */
                effect.callee_relation[user_as_inst] |= (1 << arg_no);

                assert(summary != nullptr);
                if (summary->argument_effects.size() == 0) {
                    // TODO: maybe has internal modification
                    continue;
                }
                if (arg_no >= summary->argument_effects.size()) {
                    // TODO: handle vararg
                    lerrs() << "Warning: arg_no " << arg_no << " is out of range "
                        << summary->argument_effects.size() << "\n";
                    continue;
                }
                auto &argeffect = summary->argument_effects[arg_no];
                if (argeffect.modify_type == ModifyType::MAY_MODIFY) {
                    effect.writes.insert(user_as_inst);
                }
                unsigned int argidx = 0;
                for (auto &a : call->args()) {
                    assert_eq(argidx, call->getArgOperandNo(&a));
                    if ((1 << argidx) & argeffect.tainted_args) {
                        insertElement(a, nullptr);
                    }
                    argidx++;
                }
                if (argeffect.return_taint == ReturnTaint::POINTER) {
                    insertElement(user, nullptr);
                }
            }
            // Constant that may contain global variable
            else if (const Constant *c = dyn_cast<Constant>(user)) {
                // TODO
            }
            else if (const ReturnInst *ret = dyn_cast<ReturnInst>(user)) {
                // TODO: check if returned is a pointer, or recursively has a pointer
                effect.return_taint = ReturnTaint::POINTER;
            }
            else if (const Argument *arg = dyn_cast<Argument>(user)) {
                /* func(...[%arg]...) */
                effect.tainted_args |= (1 << arg->getArgNo());
                lerrs() << "Found tainted arg(" << arg->getArgNo() << "): " << *arg << '\n';
            } else {
                if (user_as_inst) {
                    lerrs() << "Unknown Instruction (opcode=" << user_as_inst->getOpcode() << "): "
                        << *user << '\n';
                } else {
                    lerrs() << "Unknown Instruction: " << *user << '\n';
                }
            }
        }
    }

    dbg_summary() << "taints: " << effect.writes.size() << " taints found\n";
    if (effect.writes.size() <= 10) {
        for (auto &e : effect.writes) {
            dbg_summary() << *e << '\n';
        }
    }

    if (effect.return_taint == ReturnTaint::POINTER) {
        dbg_summary() << "return contains state\n";
    } else {
        dbg_summary() << "return does not contain state\n";
    }

    if (!effect.writes.empty())
        effect.modify_type = ModifyType::MAY_MODIFY;

    return effect;
}

bool FunctionAnalyzer::isMayModifyExternalSafe(const llvm::Function &f) const {
    if (phx_preset == "redis") {
        if (f.getName().startswith("dictRehash")) {
            return true;
        }
    }
    return false;
}

/* ============================== Exported helper function ============================== */

static FunctionSummary getPureSummary(size_t arg_count) {
    FunctionSummary result;

    // +1 for global variable
    for (size_t i = 0; i < arg_count + 1; ++i) {
        result.argument_effects.push_back(ArgumentEffect{
            .modify_type = ModifyType::NO_MODIFY,
            .return_taint = ReturnTaint::PURE,
            .tainted_args = 0,
        });
    }

    return result;
}

static inline bool contains(const std::unordered_set<std::string> &set, const std::string &name) {
    return set.find(name) != set.end();
}

static bool is_no_modify_with_no_return(llvm::StringRef name, const std::string &namestr) {
    static const std::unordered_set<std::string> sets = {
        // string
        "strlen", "strnlen", "strdup", "strndup",
        "bcmp", "strcasecmp", "strcmp", "strncasecmp", "strncmp", "strcoll", "strcspn",

        // we only care about memory.. file state not considered modify yet..
        "close", "open64", "openat64", "creat64", "creat",
        "fopen", "fopen64", "fclose", "fclose64",

        // ok, those are pure
        "fsync", "fdatasync", "sync_file_range",
        "feof", "ferror", "fileno",
        "ftello64",
        "access",
        "posix_fadvise64",

        // don't care..
        "fcntl", "fcntl64", "ioctl",
        "fchmod", "fchmodat", "chmod",
        "flock", "flock64",

        "getc", "ungetc",
        "write", "writev", "fwrite",
        "fputc", "fputs", "putc", "putchar", "puts",
        "printf", "fprintf", "vfprintf",

        "perror", "strerror",

        "opendir", "closedir", "readdir64", "readdir",

        "mkdir", "rmdir", "rename", "chdir", "unlink",
        "dup2", "pipe", "pipe2",

        // FIXME: may actually have memory changes to FILE* or stat buffer...
        "freopen", "fflush",
        "fseek", "lseek64",
        "fstat64", "fstat", "fstatat", "lstat64", "stat64", "stat",
        "ftruncate64", "truncate64", "ftruncate", "truncate",

        // don't handle network for now...
        "socket", "accept", "accept4", "listen", "bind", "connect", "shutdown",
        "send", "sendto", "sendmsg",
        "poll", "epoll_create", "epoll_ctl", "epoll_wait",
        "getpeername", "getsockname", "getsockopt", "setsockopt",
        "getaddrinfo", "freeaddrinfo",
        "gai_strerror",
        "inet_ntop", "inet_pton",

        // misc
        "fork", "execve", "abort", "exit", "_Exit", "_exit",
        "raise", "kill", "waitpid", "signal", "sigaction",
        "prctl",
        "sysconf",
        "umask",
        "setsid", "getpid",
        "rand", "random", "srand", "srandom",
        "_setjmp", "longjmp",
        "clock", "sleep", "usleep", "tzset",
        "setenv", "clearenv", "unsetenv",
        "isatty",
        "setlocale", "localeconv",
        "openlog", "syslog", "closelog",
        "sched_setaffinity",
        "setrlimit64",

        // memory
        "malloc", "calloc", "malloc_usable_size",
        "mmap64", "mprotect", "pkey_mprotect",

        // math
        "acos", "asin", "atan", "atan2", "cos", "cosh", "tan", "tanh", "sin", "sinh",
        "exp", "exp2", "log", "log10", "pow", "powf", "powl",
        "ldexp", "ldexpf", "ldexpl",
        "fmod", "fmodf", "fmodl",
        "atoi", "atol", "atoll",
        "lround", "lroundl", "lroundf", "llround", "llroundl", "llroundf",
        "lrint", "lrintf", "lrintl", "llrint", "llrintf", "llrintl",
        "sqrt", "sqrtf", "sqrtl",
        // TODO: actually have writes...
        "modf",

        // pthread, don't care...
        "pthread_attr_getstacksize",
        "pthread_attr_init",
        "pthread_attr_setstacksize",
        "pthread_cond_init",
        "pthread_cond_signal",
        "pthread_cond_wait",
        "pthread_create",
        "pthread_cancel",
        "pthread_join",
        "pthread_mutex_init",
        "pthread_mutex_lock",
        "pthread_mutex_trylock",
        "pthread_mutex_unlock",
        "pthread_self",
        "pthread_setcancelstate",
        "pthread_setcanceltype",
        "pthread_setname_np",
        "pthread_sigmask",

        // for now, assume there is no pointer passed to these functions...
        "llvm.abs.i32",
        "llvm.abs.i64",
        "llvm.bitreverse.i3",
        "llvm.bitreverse.i64",
        "llvm.bswap.i16",
        "llvm.bswap.i32",
        "llvm.bswap.i64",
        "llvm.ceil.f64",
        "llvm.ceil.f80",
        "llvm.ctlz.i64",
        "llvm.ctpop.i32",
        "llvm.ctpop.i64",
        "llvm.fabs.f64",
        "llvm.fabs.f80",
        "llvm.floor.f64",
        "llvm.fmuladd.f32",
        "llvm.fmuladd.f64",
        "llvm.fmuladd.v2f64",
        "llvm.fmuladd.v4f64",
        "llvm.fshl.i32",
        "llvm.fshl.i64",
        "llvm.fshr.i32",
        "llvm.fshr.i8",
        "llvm.load.relative.i64",
        "llvm.round.f32",
        "llvm.round.v4f64",
        "llvm.smax.i32",
        "llvm.smax.i64",
        "llvm.smax.i8",
        "llvm.smin.i32",
        "llvm.smin.i64",
        "llvm.smin.i8",
        "llvm.umax.i32",
        "llvm.umax.i64",
        "llvm.umin.i16",
        "llvm.umin.i32",
        "llvm.umin.i64",
        "llvm.umul.with.overflow.i64",
        "llvm.usub.sat.i32",
        "llvm.usub.sat.i64",
        "llvm.vector.reduce.add.v16i64",
        "llvm.vector.reduce.add.v2i32",
        "llvm.vector.reduce.add.v2i64",
        "llvm.vector.reduce.add.v4i32",
        "llvm.vector.reduce.add.v4i64",
        "llvm.vector.reduce.or.v2i64",
        "llvm.vector.reduce.or.v4i32",
        "llvm.vector.reduce.or.v4i64",

        // llvm
        "llvm.assume",
        "llvm.stackrestore",
        "llvm.stacksave",
        "llvm.va_copy",
        "llvm.va_end",
        "llvm.va_start",

        // FIXME: assume pure for now...
        "dladdr",
        "dlclose",
        "dlerror",
        "dlopen",
        "dlsym",
        // those actually have writes...
        "backtrace",
        "backtrace_symbols_fd",
        "getcwd", "getenv",
        "clock_gettime", "gettimeofday", "nanosleep", "ctime_r", "localtime_r", "time",
        "dirname",
        "glob64", "globfree64",
        "frexp",
        "strtod", "strtol", "strtold", "strtoll", "strtoul", "strtoull",
        "mkostemp64",
        "setitimer",
        "uname",
        "getrlimit64",
        "getrusage",
        "sigaddset",
        "sigemptyset",
    };

    return contains(sets, namestr) || name.contains("phx")
        || name.startswith("llvm.dbg")
        || name.startswith("llvm.lifetime");
}

static bool is_no_modify_with_pointer_return(llvm::StringRef name, const std::string &namestr) {
    static const std::unordered_set<std::string> sets = {
        "strchr", "strrchr",
        "strstr", "strcasestr",
        "strpbrk",
        "memcmp", "memchr",
    };

    return contains(sets, namestr);
}

static bool is_modify_1_arg_with_no_return(llvm::StringRef name, const std::string &namestr) {
    static const std::unordered_set<std::string> sets = {
        // important ones
        "free",

        "fread",
        "sprintf", "snprintf", "vsprintf", "vsnprintf",
        "qsort",
        "strftime",
    };

    return contains(sets, namestr);
}

static bool is_modify_1_arg_with_pointer_return(llvm::StringRef name, const std::string &namestr) {
    static const std::unordered_set<std::string> sets = {
        // important ones
        "realloc",
        "memset", "memcpy", "memmove",
        "strcpy", "strncpy", "strcat", "strncat",
        "fgets",
    };

    return contains(sets, namestr)
        || name.startswith("llvm.memset")
        || name.startswith("llvm.memcpy")
        || name.startswith("llvm.memmove");
}

static bool is_modify_2_arg_function_with_no_return(llvm::StringRef name, const std::string &namestr) {
    static const std::unordered_set<std::string> sets = {
        "read", "readv",
        "recv", "recvfrom",
    };

    return contains(sets, namestr);
}

bool isKnownExternalFunctions(const llvm::Function &f, const std::string &phx_preset) {

    auto name = f.getName();
    auto namestr = name.str();  // just std::string

    return is_no_modify_with_no_return(name, namestr)
        || is_no_modify_with_pointer_return(name, namestr)
        || is_modify_1_arg_with_no_return(name, namestr)
        || is_modify_1_arg_with_pointer_return(name, namestr)
        || is_modify_2_arg_function_with_no_return(name, namestr);
}

std::optional<FunctionSummary> tryGetExternalFunctionSummary(const Function &f, const std::string &phx_preset) {

    auto name = f.getName();
    auto namestr = name.str();  // just std::string

    // PURELY PURE: no modify, and return non related value
    if (is_no_modify_with_no_return(name, namestr)) {
        return getPureSummary(f.arg_size());
    }

    // no modify, but return pointer contains ARG
    if (is_no_modify_with_pointer_return(name, namestr)) {
        auto effect = getPureSummary(f.arg_size());
        effect.argument_effects.at(1) = {
            .modify_type = ModifyType::NO_MODIFY,
            .return_taint = ReturnTaint::POINTER,
            .tainted_args = 0,
        };
        return effect;
    }

    // modify the first argument, return nothing
    if (is_modify_1_arg_with_no_return(name, namestr)) {
        auto effect = getPureSummary(f.arg_size());
        effect.argument_effects.at(1) = {
            .modify_type = ModifyType::MAY_MODIFY,
            .return_taint = ReturnTaint::PURE,
            .tainted_args = 0,
        };
        return effect;
    }

    // modify the first argument, and return pointer
    if (is_modify_1_arg_with_pointer_return(name, namestr)) {
        auto effect = getPureSummary(f.arg_size());
        effect.argument_effects.at(1) = {
            .modify_type = ModifyType::MAY_MODIFY,
            .return_taint = ReturnTaint::POINTER,
            .tainted_args = 0,
        };
        return effect;
    }

    // modify the second argument, return nothing
    if (is_modify_2_arg_function_with_no_return(name, namestr)) {
        auto effect = getPureSummary(f.arg_size());
        effect.argument_effects.at(2) = {
            .modify_type = ModifyType::MAY_MODIFY,
            .return_taint = ReturnTaint::PURE,
            .tainted_args = 0,
        };
        return effect;
    }

    if (phx_preset == "redis") {
        if (name == "__assert_fail") {
            return getPureSummary(f.arg_size());
        }
        // external library functions like lua...
    }

    return std::nullopt;
}

} // namespace analysis

} // namespace phoenix
