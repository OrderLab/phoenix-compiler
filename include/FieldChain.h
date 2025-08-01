#ifndef __FIELDCHAIN_H__
#define __FIELDCHAIN_H__

#include "llvm/IR/Value.h"
#include "llvm/IR/Instructions.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/IR/Argument.h"
#include "llvm/IR/DebugLoc.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/InstVisitor.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Metadata.h"
#include "llvm/IR/Value.h"

#include "llvm/ADT/DepthFirstIterator.h"
#include "llvm/ADT/GraphTraits.h"
#include "llvm/ADT/None.h"
#include "llvm/ADT/SmallPtrSet.h"

#define unlikely(x) __builtin_expect(!!(x), 0)

namespace llvm {

struct FieldChainElem;
class FieldChain : public std::shared_ptr<FieldChainElem> {
  size_t _hash;
  size_t _len;
  static size_t calc_hash(const FieldChainElem *chain);
public:
  FieldChain(FieldChainElem *chain);
  FieldChain nest_offset(Type *type, ssize_t offset) const;
  FieldChain nest_field(Type *type, ssize_t offset) const;
  FieldChain nest_deref(void) const;
  FieldChain nest_call(Function *fun, size_t arg_no) const;
  bool operator==(const FieldChain &rhs) const;
  size_t hash() const { return _hash; }
  size_t length() const { return _len; }
};
raw_ostream &operator<<(raw_ostream &os, const FieldChain &chain);

struct FieldChainElem {
  // special offset to indicate array element
  static const ssize_t ARRAY_FIELD = LONG_MAX;

  enum class type { offset, field, deref, call } type;
  union {
    struct { Type *type; ssize_t offset; } offset;
    struct { Type *type; ssize_t field_no; } field;
    struct { Function *fun; size_t arg_no; } call;
  };
  // maybe: optimize alloc/dealloc of shared_ptr to use lifecycle-based
  FieldChain next;
};

inline FieldChain::FieldChain(FieldChainElem *chain)
  : std::shared_ptr<FieldChainElem>(chain), _hash(calc_hash(chain))
{
  _len = chain ? chain->next.length() + 1 : 0;
}

inline FieldChain FieldChain::nest_offset(Type *type, ssize_t offset) const {
  return FieldChain(new FieldChainElem{
    FieldChainElem::type::offset, { .offset = {type, offset} }, {*this}
  });
}
inline FieldChain FieldChain::nest_field(Type *type, ssize_t field_no) const {
  return FieldChain(new FieldChainElem{
    FieldChainElem::type::field, { .field = {type, field_no} }, {*this}
  });
}
inline FieldChain FieldChain::nest_deref() const {
  return FieldChain(new FieldChainElem{ FieldChainElem::type::deref, {}, {*this} });
}
inline FieldChain FieldChain::nest_call(Function *fun, size_t arg_no) const {
  return FieldChain(new FieldChainElem{
    FieldChainElem::type::call, { .call = {fun, arg_no} }, {*this}
  });
}
inline bool FieldChain::operator==(const FieldChain &rhs) const {
  if (this->hash() != rhs.hash()) return false;
  FieldChainElem *l = &**this, *r = &*rhs;
  while (l && r) {
    if (l->type != r->type) return false;
    switch (l->type) {
    case FieldChainElem::type::field:
      if (l->field.field_no != r->field.field_no) return false;
      break;
    case FieldChainElem::type::offset:
      if (l->offset.offset != r->offset.offset) return false;
      break;
    case FieldChainElem::type::call:
      if (l->call.fun != r->call.fun || l->call.arg_no != r->call.arg_no)
        return false;
      break;
    case FieldChainElem::type::deref: break;
    }
    l = &*l->next;
    r = &*r->next;
  }
  return !l && !r;
}

// maybe change to std::optional since we are already >= C++17
Optional<FieldChain> nest_gep(FieldChain chain, GetElementPtrInst *gep);
Optional<FieldChain> match_gep(FieldChain chain, const GetElementPtrInst *gep, bool *hit);
Optional<FieldChain> match_deref(FieldChain chain);

} // namespace llvm

template<>
struct std::hash<llvm::FieldChain> {
  std::size_t operator()(llvm::FieldChain const& s) const noexcept {
    return s.hash();
  }
};

namespace phoenix {
    using FieldChain = llvm::FieldChain;
}

#endif /* __FIELDCHAIN_H__ */
