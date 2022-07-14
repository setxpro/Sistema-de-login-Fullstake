require('dotenv').config()
const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const User = require('./models/User');


const app = express();

const port = 9000

// Config JSON response
app.use(express.json())
app.use(cors())


// Open Route - Public Route
app.get('/', async (req, res) => {
    res.status(200).json({msg:"Welcome API"})
});

// Private Route

app.get('/user/:id', checkToken, async(req, res) => {
    const id = req.params.id

    // Check if user exists 
    const user = await User.findById(id, '-password') // remove password url

    if (!user) {
        return res.status(404).json({msg: 'Usuário não encontrado!'})
    }

    res.status(200).json({ user })
})

// Check Token

function checkToken(req, res, next) {
    const authHeader = req.headers['authorization']
    const token = authHeader && authHeader.split(" ")[1]

    if (!token) {
        return res.status(401).json({msg: 'Acesso Negado!'})
    }

    try {
        const secret = process.env.SECRET

        jwt.verify(token, secret)

        next();

    } catch (error) {
        res.status(400).json({msg: 'Token inválido!'})
    }
}   


// Register User
app.post('/auth/register', async(req, res) => {
    const { name, email, password, confirmPassword } = req.body

    // validation

    if (!name) {
        return res.status(422).json({ msg: 'O nome é obrigatório!' })
    }
    if (!email) {
        return res.status(422).json({ msg: 'O E-mail é obrigatório!' })
    }
    if (!password) {
        return res.status(422).json({ msg: 'A senha é obrigatória!' })
    }
    if (!confirmPassword) {
        return res.status(422).json({ msg: 'Insira novamente a senha!' })
    }
    if (confirmPassword !== password) {
        return res.status(422).json({ msg: 'As senhas não são iguais!' })
    }

    // Check if user exists

    const userExists = await User.findOne({email: email}) // verify email 

    if (userExists) {
        return res.status(422).json({ msg: 'Por favor, utilize outro email!' })
    }

    // Create password
    const salt = await bcrypt.genSalt(12)
    const passwordHash = await bcrypt.hash(password, salt)

    // Create User
    const user = new User({
        name,
        email,
        password: passwordHash
    })

    try {
        
        await user.save();

        res.status(200).json({msg: 'Usuário criado com Sucesso!'})

    } catch (error) {
        console.log(error)
        res.status(500).json({msg: 'Erro com o servidor, tente novamente mais tarde!'})
    }
})

// Delete user
app.delete('/auth/delete/:id', (req, res) => {
    User.deleteOne({_id: req.params.id}, (err) => {
        if (err) return res.status(400).json({msg: 'Não foi possível deletar usuário!'})
            return res.json({msg: 'Usuário deletado com sucesso!'})
    })
})

// Login user

app.post("/auth/signin", async (req, res) => {
    const { email, password } = req.body

    // Validations
    if (!email) {
        return res.status(422).json({ msg: 'O E-mail é obrigatório!' })
    }
    if (!password) {
        return res.status(422).json({ msg: 'A senha é obrigatória!' })
    }

    // Check if user exists
    const user = await User.findOne({email: email}) // verify email 

    if (!user) {
        return res.status(404).json({ msg: 'Usuário não encontrado!' })
    }

    // Check if password match
    const checkPass = await bcrypt.compare(password, user.password)

    if (!checkPass) {
        return res.status(422).json({ msg: 'Senha inválida!' })
    }

    try {
        
        const secret = process.env.SECRET

        const token = jwt.sign(
            {
                id: user._id,
            },
            secret,
        )

        res.status(200).json({msg: 'Authenticação realizada com sucesso!', token})

    } catch (error) {
        console.log(error)
        res.status(500).json({msg: 'Erro com o servidor, tente novamente mais tarde!'})
    }
})

// Credentials 
const dbUser = process.env.DB_USER
const dbPass = process.env.DB_PASS

mongoose.connect(`mongodb+srv://${dbUser}:${dbPass}@cluster0.qcyu9kf.mongodb.net/?retryWrites=true&w=majority`).then(() => {
    console.log('Connected with Database')
}).catch(err => console.log(err))

app.listen({ port }, () => console.log(`Server Running at port:${port} 👨🏻‍🚀`))