mod tests {
    use byte::ctx::Endian;
    use byte::{TryRead, TryWrite};
    use byte_derive::{TryRead, TryWrite};
    use std::fmt::Debug;
    use zb_macros::{BitStruct};

    fn test_try_write<T: TryWrite<Endian>>(obj: T, exp_bytes: &[u8], ctx: Endian) {
        let mut bytes = [0u8; 1024];

        let size = obj.try_write(bytes.as_mut_slice(), ctx).unwrap();
        assert_eq!(size, exp_bytes.len());
        assert_eq!(&bytes[0..size], exp_bytes);
    }

    fn test_try_read<'a, T: TryRead<'a, Endian> + PartialEq + Debug>(
        bytes: &'a [u8],
        exp_obj: T,
        ctx: Endian,
    ) {
        let (obj, size) = T::try_read(bytes, ctx).unwrap();
        assert_eq!(size, bytes.len());
        assert_eq!(obj, exp_obj);
    }

    fn test_write_and_read<
        'a,
        T: TryWrite<Endian> + TryRead<'a, Endian> + PartialEq + Debug + Clone,
    >(
        obj: T,
        exp_bytes: &'a [u8],
        ctx: Endian,
    ) {
        test_try_write(obj.clone(), exp_bytes, ctx);
        test_try_read(exp_bytes, obj.clone(), ctx);
    }

    #[test]
    fn test_basic() {
        #[derive(BitStruct, Clone, PartialEq, Debug)]
        #[bit_struct(repr = u16)]
        struct Test {
            pub b1: bool,
            pub b2: bool,
            pub b3: bool,
            pub b4: bool,
            pub b5: bool,
            pub b6: bool,
            pub b7: bool,
            pub b8: bool,
            #[bit_struct(len = 8)]
            pub n: u8,
        }

        test_write_and_read(Test {
            b1: true,
            b2: false,
            b3: false,
            b4: false,
            b5: false,
            b6: false,
            b7: false,
            b8: false,
            n: 13,
        }, &[1, 13], byte::LE);
    }

    #[test]
    fn test_skip() {
        #[derive(BitStruct, Clone, PartialEq, Debug)]
        #[bit_struct(repr = u8)]
        struct Test {
            #[bit_struct(skip = 3)]
            pub a: bool,
            pub b: bool,
            #[bit_struct(skip = 1)]
            pub c: bool,
        }

        test_write_and_read(Test {
            a: true,
            b: false,
            c: true
        }, &[0b0100_1000], byte::LE);
    }

    #[test]
    fn test_enum() {
        #[derive(PartialEq, Clone, Copy, Debug, TryRead, TryWrite)]
        #[repr(u8)]
        enum E {
            A = 1,
            B = 2,
            C = 5,
        }

        #[derive(BitStruct, PartialEq, Clone, Copy, Debug)]
        #[bit_struct(repr = u8)]
        struct Test {
            #[bit_struct(len = 3)]
            pub a: E,
            pub b: bool,
            pub c: bool,
        }

        test_write_and_read(Test {
            a: E::C,
            b: true,
            c: false
        }, &[0b0000_1101], byte::LE);
    }
}

