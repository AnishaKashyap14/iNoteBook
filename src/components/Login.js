import React,{useState} from 'react'
import { useNavigate } from 'react-router-dom';
const Login = (props) => {
    const[credentials,setcredentials]=useState({email:"",password:""})
    let history=useNavigate();
    const handleSubmit=async (e)=>{
         e.preventDefault();
         const response = await fetch("http://localhost:5000/api/auth/login", {
            method: "POST",
            headers: {
              'Content-Type': 'application/json',
              },
              body: JSON.stringify({email:credentials.email,password:credentials.password})
          });
          const json=await response.json();
          console.log(json)
          if(json.success)
            {
                //save the authtoken and redirect
                localStorage.setItem('token',json.authtoken);
                history('/')
                props.showAlert("Successfully Logged in ","success")
               
            }
            else{
                //alert
                props.showAlert("Invalid details","danger")
            }
    }
    const onChange = (e) => {
        setcredentials({...credentials, [e.target.name]: e.target.value});
      };
    return (
        <div className='mt-3'>
            <h2>Login to continue to inotebook</h2>
            <form onSubmit={handleSubmit}>
                <div className="mb-3">
                    <label htmlFor="email" className="form-label">Email address</label>
                    <input type="email" className="form-control" value={credentials.email} onChange={onChange} id="email" name="email" aria-describedby="emailHelp" />
                    <div id="emailHelp" className="form-text">We'll never share your email with anyone else.</div>
                </div>
                <div className="mb-3">
                    <label htmlFor="password" className="form-label">Password</label>
                    <input type="password" className="form-control"value={credentials.password} onChange={onChange} id="password" name="password" />
                </div>

                <button type="submit" className="btn btn-primary" >Submit</button>
            </form>
        </div>
    )
}

export default Login
