//! Expanded-tree admission and clone preflight. The traversal borrows nodes;
//! it never clones a tree or formats a diagnostic containing a tree.
use super::*;

#[derive(Clone, Copy)]
pub(super) enum Node<'b, 'a> {
    Name(&'b Name<'a>),
    Type(&'b Type<'a>),
    Symbol(&'b Symbol<'a>),
    Names(&'b NameSequence<'a>),
    Params(&'b Params<'a>),
    Parsed(&'b ParseResult<'a>),
    Operator(&'b Operator<'a>),
}

pub(super) trait Tree {
    fn root(&self) -> Node<'_, '_>;
    fn check(&self, max_depth: usize, budget: &mut usize) -> Result<()> {
        let mut pending = Vec::new();
        let push = |budget: &mut usize, pending: &mut Vec<_>, node, depth| -> Result<()> {
            if depth > max_depth {
                return Err(Error::new_recursion_limit_exceeded(max_depth));
            }
            *budget = budget.checked_sub(1).ok_or(Error {
                repr: ErrorRepr::WorkLimit,
            })?;
            pending.push((node, depth));
            Ok(())
        };
        push(budget, &mut pending, self.root(), 1)?;
        while let Some((node, depth)) = pending.pop() {
            let mut children = |node| push(budget, &mut pending, node, depth + 1);
            let bytes = match node {
                Node::Name(name) => match name {
                    Name::Template(name, params) => {
                        children(Node::Name(name))?;
                        children(Node::Params(params))?;
                        0
                    }
                    Name::Operator(op) => {
                        children(Node::Operator(op))?;
                        0
                    }
                    Name::ParsedName(parsed) => {
                        children(Node::Parsed(parsed))?;
                        0
                    }
                    Name::AnonymousNamespace(id) => id.as_ref().map_or(0, String::len),
                    Name::Md5(s) | Name::NonTemplate(s) | Name::AsInterface(s) => s.len(),
                    Name::Discriminator(_) => 0,
                },
                Node::Symbol(symbol) => {
                    children(Node::Name(&symbol.name))?;
                    children(Node::Names(&symbol.scope))?;
                    0
                }
                Node::Names(names) => {
                    for name in &names.names {
                        children(Node::Name(name))?;
                    }
                    0
                }
                Node::Params(params) => {
                    for ty in &params.types {
                        children(Node::Type(ty))?;
                    }
                    0
                }
                Node::Parsed(parsed) => {
                    children(Node::Symbol(&parsed.symbol))?;
                    children(Node::Type(&parsed.symbol_type))?;
                    0
                }
                Node::Operator(op) => {
                    if let Operator::RTTITypeDescriptor(_, ty) = op {
                        children(Node::Type(ty))?;
                    }
                    0
                }
                Node::Type(ty) => match ty {
                    Type::MemberFunction(_, _, params, _, ret)
                    | Type::NonMemberFunction(_, params, _, ret) => {
                        children(Node::Params(params))?;
                        children(Node::Type(ret))?;
                        0
                    }
                    Type::MemberFunctionPointer(symbol, _, _, params, _, ret) => {
                        children(Node::Symbol(symbol))?;
                        children(Node::Params(params))?;
                        children(Node::Type(ret))?;
                        0
                    }
                    Type::CXXVBTable(names, _) | Type::CXXVFTable(names, _) => {
                        children(Node::Names(names))?;
                        0
                    }
                    Type::Ptr(ty, _)
                    | Type::Ref(ty, _)
                    | Type::RValueRef(ty, _)
                    | Type::Array(_, ty, _)
                    | Type::Var(ty, _, _) => {
                        children(Node::Type(ty))?;
                        0
                    }
                    Type::Alias(symbol, _)
                    | Type::Struct(symbol, _)
                    | Type::Union(symbol, _)
                    | Type::Class(symbol, _)
                    | Type::Enum(symbol, _) => {
                        children(Node::Symbol(symbol))?;
                        0
                    }
                    Type::ConstantString(bytes) => bytes.len(),
                    Type::None
                    | Type::VCallThunk(..)
                    | Type::TemplateParameterWithIndex(_)
                    | Type::ThreadSafeStaticGuard(_)
                    | Type::Constant(_)
                    | Type::Void(_)
                    | Type::Bool(_)
                    | Type::Char(_)
                    | Type::Schar(_)
                    | Type::Uchar(_)
                    | Type::Short(_)
                    | Type::Ushort(_)
                    | Type::Int(_)
                    | Type::Uint(_)
                    | Type::Long(_)
                    | Type::Ulong(_)
                    | Type::Int64(_)
                    | Type::Uint64(_)
                    | Type::Int128(_)
                    | Type::Uint128(_)
                    | Type::Wchar(_)
                    | Type::Char8(_)
                    | Type::Char16(_)
                    | Type::Char32(_)
                    | Type::Float(_)
                    | Type::Double(_)
                    | Type::Ldouble(_)
                    | Type::VarArgs
                    | Type::EmptyParameterPack
                    | Type::Nullptr
                    | Type::RTTIType => 0,
                },
            };
            *budget = budget.checked_sub(bytes).ok_or(Error {
                repr: ErrorRepr::WorkLimit,
            })?;
        }
        Ok(())
    }
}
macro_rules! tree {
    ($ty:ident, $variant:ident) => {
        impl Tree for $ty<'_> {
            fn root(&self) -> Node<'_, '_> {
                Node::$variant(self)
            }
        }
    };
}
tree!(Name, Name);
tree!(Type, Type);
tree!(Symbol, Symbol);
tree!(NameSequence, Names);
tree!(Params, Params);
tree!(ParseResult, Parsed);
impl Tree for (Type<'_>, StorageClass) {
    fn root(&self) -> Node<'_, '_> {
        Node::Type(&self.0)
    }
}
