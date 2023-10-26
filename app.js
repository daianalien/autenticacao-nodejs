/*importações */
require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');


const app = express();

//configuração de json (para aceitar json pq ele não vem como padrão aceita json)
app.use(express.json());


//models

const User = require('./models/User')

// open route - public route
app.get('/', (req, res)=> {
    res.status(200).json({msg: 'Say the name SEVENTEEN!'})
})

//private route

app.get("/user/:id", checkToken, async (req, res) => {

    const id = req.params.id

    // check se o usuário existe o -password é para não mostrar a senha dos usuários
    const user = await User.findById(id, '-password')

    if(!user){
        return res.status(404).json({msg: 'Usuário não encontrado'})
    }

    res.status(200).json({ user })

})

function checkToken(req, res, next){

    const authHeader = req.headers['authorization']
    const token = authHeader && authHeader.split(" ")[1]

    if(!token) {
        return res.status(401).json({ msg: 'Acesso negado'})
    }

    try {

        const secret = process.env.SECRET 

        jwt.verify(token, secret)

        next()

    } catch(error){
        res.status(400).json({ msg: 'Token inválido!'})
    }
}

//registrar usuário

app.post('/auth/register', async(req, res) => {
    const {name, email, password, confirmpassword} = req.body

    //validações
    if(!name){
        return res.status(422).json({msg: 'o nome é obrigatório!'})
    }

    if(!email){
        return res.status(422).json({msg: 'o email é obrigatório!'})
    }

    if(!password){
        return res.status(422).json({msg: 'a senha é obrigatória!'})
    }

    if(password !== confirmpassword) {
        return res.status(422).json({msg: 'os dados não conferem!'})
    }

    //check se o usuário existe

    const userExist = await User.findOne({email: email})

    if(userExist){
        return res.status(422).json({msg: 'Por favor, use outro email!'})
    }

    // criar senha

    const salt = await bcrypt.genSalt(12);
    const passwordHash = await bcrypt.hash(password, salt);

    // criação de usuário
    const user = new User({
        name, 
        email,
        password : passwordHash,
    })

    try {

        await user.save()

        res.status(201).json({msg: 'Usuário criado com sucesso'})

    } catch(error) {
        console.log(error)
        res
        .status(500)
        .json({
            msg: 'Aconteceu um erro no servidor, tente novamente mais tarde!'
        })
    }

})

// Login user

app.post("/auth/login", async (req, res) => {
    const {email, password} = req.body

    //validações
    if(!email){
        return res.status(422).json({msg: 'o email é obrigatório!'})
    }

    if(!password){
        return res.status(422).json({msg: 'a senha é obrigatória!'})
    }

    //checar se o usuário já existe

    const user = await User.findOne({ email: email})

    if(!user) {
        return res.status(404).json({ msg: 'Usuário não encontrado!'})
    }

    // check se a senha combina

    const checkPassword = await bcrypt.compare(password, user.password)

    if(!checkPassword) {
        return res.status(422).json({ msg: 'Senha inválida!'})
    }

    try {

        const secret = process.env.SECRET

        const token = jwt.sign(
            {
                id: user._id,
            },
            secret, 
        )

        res.status(200).json({msg: 'Autenticação realizada com sucesso', token})
    
    } catch(err) {
        console.log(error)
        res
        .status(500)
        .json({
            msg: 'Aconteceu um erro no servidor, tente novamente mais tarde!'
        })
    }
})



//credenciais para pegar os dados do .env

const dbUser = process.env.DB_USER;
const dbPass = process.env.DB_PASS;

mongoose
.connect(`mongodb+srv://${dbUser}:${dbPass}@cluster0.cyh9xit.mongodb.net/?retryWrites=true&w=majority`,)
.then(() => {
    app.listen(3000)
    console.log('conectou no banco')
})
.catch((err) => console.log(err))
