extern crate proc_macro;

use proc_macro::TokenStream;

use quote::quote;
// use proc_macro2::Span;
use syn::{parse_macro_input, DeriveInput, Ident, Lit, Meta, MetaList, NestedMeta};
use quote::ToTokens;

#[proc_macro_attribute]
pub fn serdes(_args: TokenStream, input: TokenStream) -> TokenStream {
    let mut item: syn::Item = syn::parse(input).unwrap();
    let impl_item = match &mut item {
        syn::Item::Impl(x) => x,
        _ => panic!("expected fn, got {:#?}", item)
    };

    // implement encode
    impl_item.items.insert(0,syn::parse(quote! {
        fn encode<'a>(&self, py: Python<'a>) -> PyResult<&'a PyBytes>  {
            let bytes = DefaultOptions::new()
                        .with_varint_encoding()
                        .serialize(&self).unwrap();

            Ok(PyBytes::new(py, &bytes))
        }
    }.into()).unwrap());

    // implement decode
    impl_item.items.insert(0,syn::parse(quote! {
        #[staticmethod]
        fn decode(bytes: &[u8]) -> Result<Self, std::io::Error> {
            let value = DefaultOptions::new()
                        .with_varint_encoding()
                        .deserialize(bytes).unwrap();

            Ok(value)
        }
    }.into()).unwrap());

    item.into_token_stream().into()
}

#[proc_macro_derive(Repr)]
pub fn derive_repr(item: TokenStream) -> TokenStream {
    let ast = parse_macro_input!(item as DeriveInput);
    let name = &ast.ident;

    let token_stream = quote! {
        #[pyproto]
        impl PyObjectProtocol for #name {
            fn __repr__(&self) -> PyResult<String> {
                Ok(format!("{:#?}", self))
            }
        }
    };

    TokenStream::from(token_stream)
}
