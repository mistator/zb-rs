use derive_more::Error;

#[derive(Error)]
pub struct TransitionError<T, E> {
    pub state: T,
    pub error: E,
}

impl<T, E> TransitionError<T, E> {
    pub fn new(state: T, error: E) -> Self {
        Self { state, error }
    }

    pub fn err<Ok>(state: T, error: E) -> Result<Ok, Self> {
        Err(Self { state, error })
    }
}

pub type TransitionResult<TOld, TNew, E> = Result<TNew, TransitionError<TOld, E>>;

pub enum Either<A, B> {
    First(A),
    Second(B),
}