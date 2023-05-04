use anonymous_tokens::sk::pp::{KeyPair, PublicParams, Token, TokenBlinded, TokenSigned};
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyBytes;

#[pyfunction]
fn generate_keypair(py: Python) -> PyResult<PyObject> {
    let mut csrng = rand::rngs::OsRng;
    let keypair = KeyPair::generate(&mut csrng);

    let serialized = bincode::serialize(&keypair);
    match serialized {
        Err(e) => Err(PyErr::new::<PyValueError, _>(format!("{}", e))),
        Ok(s) => Ok(PyBytes::new(py, &s).into())
    } 
}

#[pyfunction]
fn get_public_params(py: Python, keypair_obj: PyObject) -> PyResult<PyObject> {
    let keypair_bytes = keypair_obj.downcast::<PyBytes>(py).unwrap();
    let keypair: KeyPair = bincode::deserialize(&keypair_bytes.as_bytes()).unwrap();
    let public_params = PublicParams::from(&keypair);

    let serialized = bincode::serialize(&public_params);
    match serialized {
        Err(e) => Err(PyErr::new::<PyValueError, _>(format!("{}", e))),
        Ok(s) => Ok(PyBytes::new(py, &s).to_object(py)) 
    }
}

#[pyfunction]
fn generate_token(py: Python, public_params_obj: PyObject) -> PyResult<PyObject> {

    let mut csrng = rand::rngs::OsRng;

    let public_params_bytes = public_params_obj.downcast::<PyBytes>(py).unwrap();
    let public_params: PublicParams = bincode::deserialize(&public_params_bytes.as_bytes()).unwrap();
    let blinded_token = public_params.generate_token(&mut csrng);

    let serialized = bincode::serialize(&blinded_token);
    match serialized {
        Err(e) => Err(PyErr::new::<PyValueError, _>(format!("{}", e))),
        Ok(s) => Ok(PyBytes::new(py, &s).to_object(py)) 
    }
}

#[pyfunction]
fn sign_token(py: Python, keypair_obj: PyObject, blinded_token_obj: PyObject) -> PyResult<PyObject> {
    let keypair_bytes = keypair_obj.downcast::<PyBytes>(py).unwrap();
    let keypair: KeyPair = bincode::deserialize(&keypair_bytes.as_bytes()).unwrap();

    let blinded_token_bytes = blinded_token_obj.downcast::<PyBytes>(py).unwrap();
    let blinded_token: TokenBlinded = bincode::deserialize(&blinded_token_bytes.as_bytes()).unwrap();

    let signed_token = keypair.sign(&blinded_token.to_bytes());
    if signed_token.is_none() {
        return Err(PyErr::new::<PyValueError, _>("Failed to sign token"));
    }

    let serialized = bincode::serialize(&signed_token.unwrap());
    match serialized {
        Err(e) => Err(PyErr::new::<PyValueError, _>(format!("{}", e))),
        Ok(s) => Ok(PyBytes::new(py, &s).to_object(py)) 
    }
}

#[pyfunction]
fn unblind_token(py: Python, blinded_token_obj: PyObject, signed_token_obj: PyObject) -> PyResult<PyObject> {
    let blinded_token_bytes = blinded_token_obj.downcast::<PyBytes>(py).unwrap();
    let blinded_token: TokenBlinded = bincode::deserialize(&blinded_token_bytes.as_bytes()).unwrap();

    let signed_token_bytes = signed_token_obj.downcast::<PyBytes>(py).unwrap();
    let signed_token: TokenSigned = bincode::deserialize(&signed_token_bytes.as_bytes()).unwrap();

    let token = blinded_token.unblind(signed_token);
    if token.is_err() {
        return Err(PyErr::new::<PyValueError, _>("Failed to unblind token"));
    }

    let serialized = bincode::serialize(&token.unwrap());
    match serialized {
        Err(e) => Err(PyErr::new::<PyValueError, _>(format!("{}", e))),
        Ok(s) => Ok(PyBytes::new(py, &s).to_object(py)) 
    }
}

#[pyfunction]
fn verify_token(py: Python, keypair_obj: PyObject, token_obj: PyObject) -> PyResult<bool> {
    let keypair_bytes = keypair_obj.downcast::<PyBytes>(py).unwrap();
    let keypair: KeyPair = bincode::deserialize(&keypair_bytes.as_bytes()).unwrap();
    
    let token_bytes = token_obj.downcast::<PyBytes>(py).unwrap();
    let token: Token = bincode::deserialize(&token_bytes.as_bytes()).unwrap();

    let result = keypair.verify(&token);
    Ok(result.is_ok())
}

#[pymodule]
fn tokenlib(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_wrapped(wrap_pyfunction!(generate_keypair))?;
    m.add_wrapped(wrap_pyfunction!(get_public_params))?;
    m.add_wrapped(wrap_pyfunction!(generate_token))?;
    m.add_wrapped(wrap_pyfunction!(sign_token))?;
    m.add_wrapped(wrap_pyfunction!(unblind_token))?;
    m.add_wrapped(wrap_pyfunction!(verify_token))?;
    Ok(())
}

