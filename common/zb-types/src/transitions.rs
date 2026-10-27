use derive_more::Error;

#[derive(Error, Debug)]
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

impl<A, B> Either<A, B> {
    pub fn first(&self) -> Option<&A> {
        match self {
            Either::First(first) => Some(first),
            Either::Second(_) => None,
        }
    }

    pub fn second(&self) -> Option<&B> {
        match self {
            Either::First(_) => None,
            Either::Second(second) => Some(second),
        }
    }
}
