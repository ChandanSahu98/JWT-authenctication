const express = require('express');
const app = express();
const jwt = require("jsonwebtoken");
app.use(express.json());

const users = [
    {
        id : "1",
        username: "john",
        password: "John00",
        isAdmin: "true",
    },
    {
        id: "2",
        username: "jane",
        password: "Jane00",
        isAdmin: false
    }
];


//pusrposely used to store token and if user log out then we will delete all tokens in this token arary.
//seperately we want to use database to store this.
let refreshtokenArray = [];

app.post("/api/refresh", (req, res)=>{
    //take the refresh token from the user
    const refreshtoken = req.body.token;

    //send error if there is no token or its invalid
    if(!refreshtoken) return res.status(401).json("You are not authenticated!");
    if(!refreshtokenArray.includes(refreshtoken)){
        return res.status(403).json("Refresh token is not valid");
    }
    jwt.verify(refreshtoken, "myRefreshSecretKey", (err, user) => {
        err && console.log(err);
        refreshtokenArray = refreshtokenArray.filter((token)=> token !== refreshtoken);

        const newAccessToken = generateAccessToken(user);
        const newRefreshToken = generateRefreshToken(user);
        refreshtokenArray.push(newRefreshToken);
        res.status(200).json({
            accessToken: newAccessToken,
            refreshtoken: newRefreshToken
        });
    });

    //if everything fine, create new access token and send to user

})

const generateAccessToken = (user) => {
    return jwt.sign(
        {id: user.id, isAdmin: user.isAdmin},
        "mySecretKey",
        {expiresIn: "5s"}
    )
}
const generateRefreshToken =(user) => {
    return jwt.sign(
        {id: user.id, isAdmin: user.isAdmin},
        "myRefreshSecretKey"
    )
}

app.post("/api/login", (req, res) => {
    const {username, password} = req.body;
    const user = users.find(u => {
        return u.username === username && u.password === password;
    });
    if(user){
        //Generate a access token.
        const accessToken = generateAccessToken(user);
        const refreshToken = generateRefreshToken(user);
        refreshtokenArray.push(refreshToken);
        res.json({
            username: user.username,
            isAdmin: user.isAdmin,
            accessToken,
            refreshToken
        });
    }
    else{
        res.status(400).json("Username and password is wrong!")
    }

});


//Creating a middleware which verify JWT Token and send res accordingly.
const verify = (req, res, next) => {
    const authHeader = req.headers.authorization;
    if(authHeader){
        const token = authHeader.split(" ")[1];

        jwt.verify(token, "mySecretKey", (err, user)=>{
            if(err){
                return res.status(403).json("Token is not valid or expired!");
            }

            req.user = user;
            next();
        });
    }
    else{
        res.status(401).json("You are not authenticated");
    }
};

app.delete("/api/users/:userId", verify, (req,res) => {
    if(req.user.id === req.params.userId || req.user.isAdmin){
        res.status(200).json("User Deleted Successfully");
    }
    else{
        res.status(403).json("You are not allowed to Delete this user!");
    }
});

app.post("/api/logout", verify, (req, res) => {
    const refreshToken = req.body.token;
    refreshtokenArray = refreshtokenArray.filter((token) => token !== refreshToken);
    res.status(200).json("You logged out Successfully!");
});


app.listen(5000, () => console.log("Backend server started At 5000"));