#include "FieldChain.h"
#include "Utils.h"

namespace llvm {

size_t FieldChain::calc_hash(const FieldChainElem *chain) {
  if (chain == nullptr) return 0;
  size_t hash = chain->next.hash();
  switch (chain->type) {
  case FieldChainElem::type::field:
    hash = std::hash<ssize_t>{}(chain->field.field_no) ^ (hash << 1);
    break;
  case FieldChainElem::type::deref:
    hash = std::hash<int32_t>{}(0xdeadbeef) ^ (hash << 1);
    break;
  case FieldChainElem::type::offset:
    hash = std::hash<ssize_t>{}(chain->offset.offset) ^ (hash << 1);
    break;
  case FieldChainElem::type::call:
    hash = std::hash<Function *>{}(chain->call.fun) ^ (hash << 1);
    hash = std::hash<size_t>{}(chain->call.arg_no) ^ (hash << 1);
    break;
  }
  return hash;
}

raw_ostream &operator<<(raw_ostream &os, const FieldChain &chain) {
  FieldChainElem *node = &*chain;
  char s[20];
  snprintf(s, 20, "#%016lx", chain.hash());
  os << s << '{';
  if (node)
    os << "outermost";
  while (node) {
    switch (node->type) {
    case FieldChainElem::type::offset:
      os << "@(" << node->offset.offset << ')'; break;
    case FieldChainElem::type::field:
      os << "." << "field(" << node->field.field_no << ")" /*node->field.type */; break;
    case FieldChainElem::type::call:
      break;
    case FieldChainElem::type::deref:
      os << '^'; break;
    default:
      os << "(unknown)"; break;
    }
    node = &*node->next;
  }
  os << '}';
  return os;
}

/*
 * Decompose GEP into multiple elements in the chain.
 *
 * Any GEP instruction like `GEP $x, n, f1, f2, ...` can be composed by:
 *   $1 = GEP $x, n (if n != 0)
 *   $2 = GEP $1, 0, f1
 *   $3 = GEP $2, 0, f2
 * We store the first relationship as an `offset` which would be common for
 * arrays, and the second and third as `field`s. The elements will be added
 * to the chain in reverse order.
 */
Optional<FieldChain> nest_gep(FieldChain chain, GetElementPtrInst *gep) {
  unsigned operands = gep->getNumOperands();

  // Decompose all fields
  while (operands-- > 2) {
    if (ConstantInt *field = dyn_cast<ConstantInt>(gep->getOperand(operands))) {
      chain = chain.nest_field(NULL, field->getSExtValue());
    } else {
      chain = chain.nest_field(NULL, FieldChainElem::ARRAY_FIELD);
    }
  }

  // Add offset operand to the chain.
  // If it is 0, then skip it. For other constant, add the constant value.
  // If it is a variable, add ARRAY_FIELD to the offset.
  // When doing matching, a variable operand in the given GEP can may either
  // field or const, or a missing 0. Otherwise, it will exact match consts.
  if (ConstantInt *offset = dyn_cast<ConstantInt>(gep->getOperand(1))) {
    // Ignore zero offset. We may consider allow any const offset as
    // array offset in the future (a more relaxed constraint).
    if (!offset->isZero()) {
      chain = chain.nest_offset(NULL, offset->getSExtValue());
    }
  } else {
    // This may be a variable, allow arbitrary array offset
    chain = chain.nest_offset(NULL, FieldChainElem::ARRAY_FIELD);
  }
  return chain;
}

/*
 * Try to match the chain with a GEP instruction. For decomposition rule,
 * refer to `nest_gep` function. The matching will be in GEP operand order.
 *
 * If the argument chain is not root, then it will match the prefix and return
 * the remnant. If the remnant is exactly the root (i.e. nullptr), then the
 * root will be returned. However, if it matched pass the root (i.e. accesses
 * some field), then None will be returned, so the caller will not proceed,
 * but this instruction should be added to the hit points.
 *
 * If the argument chain is already root: then if it only has offset operand,
 * the exact match root will be returned, and hit is set to true. Otherwise,
 * for any field match, it will return None, so the caller will not proceeed.
 *
 * Caller should always check the hit variable.
 *
 * TODO: type matching
 */
Optional<FieldChain> match_gep(FieldChain chain, const GetElementPtrInst *gep, bool *hit) {
  const unsigned operands = gep->getNumOperands();
  bool dummy_hit;
  if (!hit) hit = &dummy_hit;
  *hit = false;
  if (unlikely(operands <= 1)) {
    phoenix::lerrs() << "Invalid GEP instruction: " << *gep << '\n';
    return None;
  }
  if (chain.get() == nullptr) {
    // any dereference to root is always hit
    *hit = true;
    // Only offset
    if (operands == 2) {
      return chain;
    } else {
      return None;
    }
  }

  // Match offset operand first.
  if (ConstantInt *offset = dyn_cast<ConstantInt>(gep->getOperand(1))) {
    // Ignore zero offset.
    if (!offset->isZero()) {
      if (chain->type == FieldChainElem::type::offset &&
          chain->offset.offset == offset->getSExtValue()) {
        chain = chain->next;
      } else {
        return None;
      }
    }
  } else {
    // It may be a variable. We allow either const or var, as long as it is
    // offset type on the chain.
    if (chain->type != FieldChainElem::type::offset)
      return None;
    // This may be a variable, allow arbitrary array offset
    chain = chain->next;
  }
  // Early return if we reached root at any level of the match
  if (chain.get() == nullptr) {
    *hit = true;
    return operands == 2 ? Optional(chain) : None;
  }

  // Match all the fields
  for (unsigned op = 2; op < operands; ++op) {
    if (chain->type != FieldChainElem::type::field)
      return None;
    if (ConstantInt *field = dyn_cast<ConstantInt>(gep->getOperand(op))) {
      if (chain->field.field_no == field->getSExtValue()) {
        chain = chain->next;
      } else {
        return None;
      }
    } else {
      chain = chain->next;
    }
    // Early return if we reached root at any level of the match
    if (chain.get() == nullptr) {
      *hit = true;
      return op == operands - 1 ? Optional(chain) : None;
    }
  }
  return chain;
}

Optional<FieldChain> match_deref(FieldChain chain) {
  if (chain.get() == nullptr || chain->type != FieldChainElem::type::deref)
    return None;
  return chain->next;
}

}
