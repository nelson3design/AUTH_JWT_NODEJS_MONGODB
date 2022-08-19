

require('dotenv').config()

const express = require('express')
const mongoose = require('mongoose')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')

const app = express()

app.use(express.json())

const port= process.env.PORT || 5000

app.get('/',(req, res)=>{

    res.status(200).json({msg: "hello world"})

})

// import model
const User = require('./models/User')

// private route

app.get('/user/:id', checkToken, async(req,res)=>{

    const id = req.params.id

    const user = await User.findById(id, '-password') // excluir a senha ('-password')
    

    if(!user){
        return res.status(404).json({msg: 'Usuário não encontrado!'})
    }

    res.status(200).json({user})

})

function checkToken(req, res, next){

    const authHeader= req.headers['authorization']

    const token = authHeader && authHeader.split(" ")[1]

    if(!token){
        return res.status(401).json({msg: 'Acesso negado!'})
    }

    try {

     const secret = process.env.secret
     jwt.verify(token,secret)

      next()

    } catch (error) {
        res.status(400).json({ msg: 'token inválido!' })

    }
}


//register

app.post('/auth/register', async(req, res)=>{
    const {name, email, password, confirmPassword} = req.body

    if(!name){
        res.status(422).json({msg: 'o nome é obrigatório!'})
    }
    if (!email) {
        res.status(422).json({ msg: 'o email é obrigatório!' })
    }
    if (!password) {
        res.status(422).json({ msg: 'a senha é obrigatório!' })
    }
     
    if (password !== confirmPassword) {
        res.status(422).json({ msg: 'as senhaa não conferem!' })
    }


   // check if user exist

    const userExist = await User.findOne({email : email}) 

    if(userExist){
        res.status(422).json({ msg: 'email já existe, por favor utilize outro email!' })
    }

   // create password

   const salt = await bcrypt.genSalt(12)

   const passwordHash = await bcrypt.hash(password, salt)


   // create user

   const user = new User({
       name,
       email,
       password: passwordHash
   })

   try {

    await user.save()

    res.status(201).json({msg: 'Usuário criado com sucesso!'})
    
   } catch (error) {
    res.status(500).json({msg: 'Aconteceu um erro no servidor, tente novamente mais tarde!'})
    
   }


})


//login

app.post('/auth/login', async(req, res)=>{

    const {email, password} = req.body

  
    if (!email) {
        res.status(422).json({ msg: 'o email é obrigatório!' })
    }
    if (!password) {
        res.status(422).json({ msg: 'a senha é obrigatório!' })
    }

    // check if user exist

    const user = await User.findOne({ email: email })

    if (!user) {
        res.status(422).json({ msg: 'usuário não encontrado!' })
    }

     // check if password match

     const checkPassword = await bcrypt.compare(password, user.password)

    if (!checkPassword){
        res.status(422).json({ msg: 'Senha inválida!' })
    }

    try {
     
        const secret = process.env.secret

        const token = jwt.sign(
            {
                id: user._id
            },
            secret
        )
       

        res.status(200).json({ msg: 'Autenticação realizado com sucesso!',token })

    } catch (error) {
        res.status(500).json({ msg: 'Aconteceu um erro no servidor, tente novamente mais tarde!' })

    }


})

const dbUser = process.env.DB_USER
const dbPass = process.env.DB_PASS



mongoose.connect(`mongodb+srv://${dbUser}:${dbPass}@cluster0.u9nnfzj.mongodb.net/?retryWrites=true&w=majority`).then(()=>{

    app.listen(port,()=>{
      console.log(`api rodando na porta ${port}`)
    })

}).catch((error)=> console.log(error))    


