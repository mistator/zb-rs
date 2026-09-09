use quote::{ToTokens, quote};
use syn::punctuated::Punctuated;
use syn::{FnArg, ReceiverKind, Type};

pub struct ImplBlock {
    pub item_impl: syn::ItemImpl,
}

impl ImplBlock {
    fn item_to_tokens(&self, item: &syn::ImplItem, receiver: ReceiverKind, tokens: &mut proc_macro2::TokenStream) {
        match item {
            syn::ImplItem::Fn(fn_) => {
                let syn::ImplItemFn { attrs, vis, sig, .. } = fn_;
                let fn_name = &sig.ident;
                let fn_args = sig.inputs
                    .clone()
                    .into_iter()
                    .filter_map(|input| {
                        match input {
                            FnArg::Receiver(_) => None,
                            FnArg::Typed(arg) => Some(arg.pat),
                        }
                    })
                    .map(|input| input)
                    .collect::<Punctuated<_, syn::Token![,]>>();

                let (receiver_type, receiver) = match receiver {
                    ReceiverKind::Value => (quote!(Self), quote!(self)),
                    ReceiverKind::Reference(_, _, _) => (quote!(&Self), quote!(&self)),
                    _ => panic!("invalid receiver")
                };

                tokens.extend(quote! {
                    #(#attrs)*
                    #vis #sig {
                        <#receiver_type>::#fn_name(#receiver, #fn_args)
                    }
                });
            }
            _ => panic!("unsupported trait item, only fn is supported"),
        }
    }
}

impl ToTokens for ImplBlock {
    fn to_tokens(&self, tokens: &mut proc_macro2::TokenStream) {
        let syn::ItemImpl { generics, attrs, trait_, self_ty, .. } = &self.item_impl;

        let mut items_stream_value = proc_macro2::TokenStream::new();
        let mut items_stream_ref = proc_macro2::TokenStream::new();
        for item in &self.item_impl.items {
            self.item_to_tokens(item, ReceiverKind::Value, &mut items_stream_value);
            self.item_to_tokens(item, ReceiverKind::Reference(syn::token::And::default(), None, None), &mut items_stream_ref);
        }

        let self_ty = match self_ty.as_ref() {
            Type::Reference(ref_) => ref_.elem.clone(),
            _ => panic!("only implementation for references of path types is supported"),
        };
        if !matches!(self_ty.as_ref(), Type::Path(_)) {
            panic!("only implementation for references of path types is supported");
        }

        let mut trait_tokens = proc_macro2::TokenStream::new();
        match trait_ {
            None => {},
            Some((path, for_)) => {
                path.to_tokens(&mut trait_tokens);
                for_.to_tokens(&mut trait_tokens);
            },
        };

        let item_impl = &self.item_impl;
        tokens.extend(quote! {
            #item_impl

            #(#attrs)*
            impl<#generics> #trait_tokens #self_ty {
                #items_stream_ref
            }

            #(#attrs)*
            impl<#generics> #trait_tokens &mut #self_ty {
                #items_stream_value
            }
        });
    }
}
