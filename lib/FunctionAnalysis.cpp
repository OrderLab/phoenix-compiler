#include "llvm/ADT/MapVector.h"
#include "llvm/Analysis/TargetLibraryInfo.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/InstrTypes.h"
#include "llvm/IR/Instruction.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Operator.h"
#include "llvm/IR/PassManager.h"
#include "llvm/IR/Value.h"
#include "llvm/Pass.h"
#include "llvm/Support/Casting.h"
#include "llvm/Support/raw_ostream.h"

#include <mutex>
#include <unordered_map>
#include <unordered_set>
#include <queue>

#include "Utils.h"
#include "FieldChain.h"
#include "FunctionAnalysis.h"

using namespace llvm;

namespace phoenix {

namespace analysis {

FunctionAnalyzer::FunctionAnalyzer(const Function &f,
        const FunctionSummaryMap &summaries, std::shared_mutex *summary_lock)
    : f(f), summaries(summaries), summary_lock(summary_lock)
{}

FunctionSummary FunctionAnalyzer::analyze() {
    FunctionSummary result;

    int i = 0;
    for (auto &it : f.args()) {
        dbg_summary() << "=== Analyzing arg " << i++ << '\n';
        result.argument_effects.push_back(analyzeSingleArgument(it));
    }

    return result;
}

ArgumentEffect FunctionAnalyzer::analyzeSingleArgument(const Argument &arg) const {

    typedef std::queue<std::tuple<const Value *, FieldChain, ssize_t>> VisitQueue;
    typedef std::unordered_map<const Value *, bool> VisitedNodeSet;

    ArgumentEffect effect = {
        ModifyType::NO_MODIFY,
        ReturnTaint::PURE,
        {},
    };

    VisitedNodeSet visited;
    VisitQueue queue;

    // visited[dyn_cast<Value>(&arg)] = true;
    visited[&arg] = true;
    queue.push({&arg, nullptr, 0});

    auto insertElement = [&visited, &queue](const Value *elem, const FieldChain &chain) {
        if (visited[elem]) return;
        // dbg() << "Added: " << *elem << '\n';
        queue.push({elem, chain, 0});
        visited[elem] = true;
    };

#define returnTrueIfScoped do {} while (0)

    while (!queue.empty()) {
        auto [elem, chain, y] = queue.front();
        queue.pop();

        // dbg() << "=====\n";

        // dbg() << *elem << '\n';

        for (const Use &use : elem->uses()) {
            const User *user = use.getUser();
            // dbg() << "processing user " << *user << '\n';

            // TODO: handle global variable
            if (!isa<Instruction>(user) && !isa<ReturnInst>(user)) continue;

            auto user_as_inst = dyn_cast<Instruction>(user);

            if (const StoreInst *store = dyn_cast<StoreInst>(user)) {
                if (elem == store->getOperand(0)) {
                    // If it was the src operand, search for definition of dst, add deref
                    // to the chain.
                    insertElement(store->getOperand(1), chain.nest_deref());
                } else {
                    if (chain.get() == nullptr)
                        effect.taints.insert(user_as_inst);

                    // If it was the dst operand, search for usage of src, remove one
                    // deref from chain.
                    auto newchain = match_deref(chain);
                    if (newchain.hasValue()) {
                        if (newchain.getValue().get() == nullptr)
                            returnTrueIfScoped;
                        insertElement(store->getOperand(0), newchain.getValue());
                    }
                }
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
                dbg() << "Unsupported Instruction: " << *user << '\n';
            } else if (isa<InsertValueInst>(user)) {
                // TODO
                dbg() << "Unsupported Instruction: " << *user << '\n';
            } else if (const CallBase *call = dyn_cast<CallBase>(user)) {
                // if (call->isDebugOrPseudoInst()) continue;

                auto callee = call->getCalledFunction();
                std::shared_lock<std::shared_mutex> guard;
                if (summary_lock)
                    guard = std::shared_lock(*summary_lock);
                auto it = summaries.find(callee);
                if (it == summaries.end()) {
                    if (callee == call->getCaller()) {
                        dbg() << "Warning: Direct recursion handling TODO!\n";
                    } else {
                        dbg() << "Warning: Indirect call not handled!\n";
                    }
                } else {
                    auto arg_no = call->getArgOperandNo(&use);

                    // TODO use bitmap as argument taint
                    if (it->second.argument_effects.size() == 0)
                        continue;
                    auto &argeffect = it->second.argument_effects[arg_no];
                    if (argeffect.modify_type == ModifyType::MAY_MODIFY)
                        effect.taints.insert(user_as_inst);
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
                dbg() << "unknown\n";
            }
        }
    }

    dbg_summary() << "taints: " << effect.taints.size() << " taints found\n";
    if (effect.taints.size() <= 10) {
        for (auto &e : effect.taints) {
            dbg_summary() << *e << '\n';
        }
    }

    if (effect.return_taint == ReturnTaint::POINTER) {
        dbg_summary() << "return contains state\n";
    } else {
        dbg_summary() << "return does not contain state\n";
    }

    if (!effect.taints.empty())
        effect.modify_type = ModifyType::MAY_MODIFY;

    return effect;
}

} // namespace analysis

} // namespace phoenix
