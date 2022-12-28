const express = require('express')
const cors = require('cors')
const app = express()
const bodyParser = require('body-parser')
const mysql = require('mysql2');
const jwt = require('jsonwebtoken');
require('dotenv').config()
app.use(cors())
app.use(bodyParser.json())
const connection = mysql.createConnection(process.env.DATABASE_URL)
const bcrypt = require('bcrypt');
const saltRounds = 15;
const secret = process.env.SECRET
const secretUser = process.env.SECRET_USER
app.post('/addscore',(req,res) => {
    const token_c  = req.headers.authorization
    const name = req.body.name 
    const score = req.body.score
    if(token_c){
        const token = token_c.split(" ")[1]
        try{
            jwt.verify(token, secret, function(err, decoded) {
               if(err){
                throw err
               }else{
                connection.query(
                    'INSERT INTO tb_score (name,score) VALUES (?,?)',[name,score],(err,results) => {
                            if(err){ throw err }
                            if(results.affectedRows > 0){
                                res.json({err:false,result:results,msg:'add score successfully'})
                            }
                           
                    }
                )
               }
              });
            }catch(err) {
                res.json({
                    err:true,
                    msg:err
                })
            }
    }else{
        res.json({
            err:true,
            msg:'Token invalid'
        })
    }
})
app.delete('/delete',(req,res) => {
    const token_c  = req.headers.authorization
    const id = req.body.id
    if(token_c){
        const token = token_c.split(" ")[1] ;
        try{
            jwt.verify(token, secret, function(err, decoded) {
               if(err){
                throw err
               }else{
                connection.query(
                    'DELETE FROM tb_score WHERE id = ?',[id],(err,results) => {
                            if(err){ throw err }
                            if(results.affectedRows > 0){
                                res.json({err:false,result:results,msg:'delete score successfully'})
                            }
                           
                    }
                )
               }
              });
            }catch(err) {
                res.json({
                    err:true,
                    msg:err
                })
            }
    }else{
        res.json({
            err:true,
            msg:'Token invalid'
        })
    }
})
app.get('/', function (req, res) {
    res.json({msg: 'Hello'})
})
app.get('/score', function (req, res) {
    connection.query(
        'SELECT * FROM tb_score ORDER BY score DESC LIMIT 0,5',
        function(err, results) {
            if(err) { throw err }
            res.json({results: results})
        }
      );
})
app.get('/scoreall', function (req, res) {
    connection.query(
        'SELECT * FROM tb_score ORDER BY score DESC',
        function(err, results) {
            if(err) { throw err }
            res.json({results: results})
        }
      );
})
app.post('/update',(req,res) => {
    const score = req.body.score
    const name = req.body.name 
    const id = req.body.id
    const token_c = req.headers.authorization 
    if(!score ||!name ||!id){
        res.json({err:true,msg:'data empty'})
    }else{
    if(token_c){    
        const token = token_c.split(" ")[1]
        try{
            jwt.verify(token, secret, function(err, decoded) {
               if(err){
                throw err
               }else{
                connection.query(
                    'UPDATE tb_score set name = ? , score = ? WHERE id = ?',[name,score,id],(err,results) => {
                            if(err){ throw err }
                            if(results.affectedRows > 0){
                                res.json({err:false,result:results,msg:'update score successfully'})
                            }
                           
                    }
                )
               }
              });
            }catch(err) {
                res.json({
                    err:true,
                    msg:err
                })
            }
    }else{
        res.json({
            err:true,
            msg:'Token invalid'
        })
    }
}
})
app.post('/scoreperid', function (req, res) {
    const id = req.body.id
    connection.query(
        'SELECT * FROM tb_score WHERE id = ?',[id],
        function(err, results) {
            if(err) { throw err }
            res.json({results: results})
        }
      );
})
app.post('/register', function (req, res) {
    const username = req.body.username
    const password = req.body.password
    const position = req.body.position 
    const role = 'user'
    bcrypt.genSalt(saltRounds, function(err, salt) {
        bcrypt.hash(password, salt, function(err, hash) {
            connection.query(
                'INSERT INTO tb_admin2 (username,password,position__,role) VALUES (?,?,?,?)',[username,hash,position,role],
                function(err, results) {
                    if(err) { throw err }
                    if(results.affectedRows > 0){
                        res.json({results: results})
                    }
                }
              );
        });
    });
   
})
app.post('/login',(req,res) => {
    const username = req.body.username
    const password = req.body.password
    connection.query(
        'SELECT * FROM tb_admin2 WHERE username = ?',[username],
        function(err, results) {
            if(err) { throw err }
            if(results.length > 0){
                const password_user = results[0].password;
                
                bcrypt.compare(password, password_user, function(err, result) {
                    if(err){throw err ;}
                    if(result){
                        const role = results[0].role ;
                        if(role == 'admin'){
                        const  token = jwt.sign({ username: username}, secret,{expiresIn: '5h'});
                        const  tokenAdminUser = jwt.sign({ username: username}, secret,{expiresIn: '5h'});
                        res.json({err:false,msg:'Hello admin',token:token,token_user:tokenAdminUser})
                    }else{
                        const tokenUser = jwt.sign({username:username},secretUser,{expiresIn:'2h'})
                        res.json({msg:'Hello member',token_user:tokenUser})
                    }  
                    }else {
                        res.json({err:true,msg:'username or password invalid'})
                    }
                });
             
            }else{
                res.json({err:true,msg:'username or password invalid'})
            }
        }
      );
})
app.post('/adminauthen',(req,res) => {
    const token = req.headers.authorization.split(" ")[1]
    try{
    jwt.verify(token, secret, function(err, decoded) {
       if(err){
        throw err
       }else{
        res.json({
            err:false,
            result:decoded
        })
       }
      });
    }catch(err) {
        res.json({
            err:true,
            msg:err
        })
    }
})
app.listen(process.env.PORT || 5001, function () {
  console.log('Server is running..')
})