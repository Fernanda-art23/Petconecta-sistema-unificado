const express = require('express');
const cors = require('cors');
const mysql = require('mysql2/promise');
const crypto = require('crypto'); 

const porta = 3000;
const app = express();
const pool = require('./db'); 


app.use(cors());
app.use(express.json()); 

app.listen(porta, () => {
    console.log("Servidor rodando na porta:", porta);
});

// ROTA HASH
app.get("/hash", async (req, res) => {
    try {
        
        let { senha_usuario } = req.body || {}; 
        
        if (!senha_usuario) {
            return res.status(400).send("Preencha uma senha");
        }

        senha_usuario = senha_usuario.trim().replace("ㅤ", "");

        if (senha_usuario.length < 6) {
            return res.status(400).send("A senha tem que conter no mínimo 6 caracteres");
        }

        const hash = crypto.createHash("sha256").update(senha_usuario).digest("hex");
        res.send(`Hash SHA256: ${hash}`);
    } catch (error) {
        console.error('Erro na rota /hash:', error);
        res.status(500).send("Erro interno.");
    }
});

// ROTA FALECONOSCO
app.post("/faleconosco", async (req, res) => { 
    try {
      const { nome_completo, email, telefone, assunto, mensagem } = req.body;
      
      
      if (!nome_completo || !email || !telefone || !assunto || !mensagem) {
        return res.status(400).json({ resposta: "Preencha todos os campos obrigatórios" });
      }

      if (mensagem.length < 6) {
        return res.status(400).json({ "resposta": "A mensagem deve conter no mínimo 6 caracteres" });
      } else if (email.length < 6) {
        return res.status(400).json({ "resposta": "Preencha um e-mail válido" });
      } else if (nome_completo.length < 6) {
        return res.status(400).json({ "resposta": "Preencha o seu nome inteiro" });
      } else if (telefone.length < 8) {
        return res.status(400).json({ "resposta": "Preencha o seu telefone" });
      } else if (assunto.length < 5) {
        return res.status(400).json({ "resposta": "Preencha com o assunto da conversa" });
      }
      
      
      const sql = `INSERT INTO petconecta (nome_completo, email, telefone, assunto, mensagem) VALUES (?,?,?,?,?)`;
      const [resultado2] = await pool.query(sql, [nome_completo, email, telefone, assunto, mensagem]);
      
      if (resultado2.affectedRows === 1) {
          res.status(201).json({ "resposta": "Mensagem enviada com sucesso!" }); 
      } else {
          res.status(500).json({ "resposta": "Erro ao enviar mensagem." }); 
      }

    } catch (error) {
      console.error('ERRO NO FALE CONOSCO:', error);
      res.status(500).json({ resposta: "Erro interno do servidor." });
    }
}); // FIM DA ROTA FALECONOSCO

// RoTA CADASTRO
app.post("/cadastro", async (req, res) => { // 👈 INÍCIO DA ROTA /cadastro
    try {
        let { nome_completo, email, senha } = req.body;
        
        // Limpeza e validação básica
        if (!nome_completo || !email || !senha) {
            return res.status(400).json({ "resposta": "Preencha todos os campos obrigatórios." });
        }

        senha = senha.trim().replace("ㅤ", "");

        if (senha.length < 6) {
            return res.status(400).json({ "resposta": "A senha tem que conter no mínimo 6 caracteres." });
        }
        
        let sql = `SELECT * FROM cadastro WHERE email = ?`;
        let [resultadosConsulta] = await pool.query(sql, [email]);

        if (resultadosConsulta.length !== 0) {
            return res.status(409).json({ "resposta": "Email já cadastrado!" }); // 409 Conflict
        }

       
        const hash = crypto.createHash("sha256").update(senha).digest("hex");

        sql = `INSERT INTO cadastro (nome_completo, email, senha) VALUES (?, ?, ?)`;
       
        let [resultadoInsercao] = await pool.query(sql, [nome_completo, email, hash]);

        if (resultadoInsercao.affectedRows === 1) {
            res.status(201).json({ "resposta": "Cadastro efetuado com sucesso!" }); // 201 Created
        } else {
            return res.status(500).json({ "resposta": "Erro ao fazer cadastro!" });
        }

    } catch (error) {
        console.error('ERRO NO CADASTRO:', error);
        res.status(500).json({ "resposta": "Erro interno do servidor." });
    }
}); // FIM DA ROTA /cadastro

//ROTA LOGIN
app.post('/login', async (req, res) => {
    const { email, senha } = req.body; 
    
    if (!email || !senha) {
        return res.status(400).json({ mensagem: "Preencha e-mail e senha." });
    }

    try {
       
        const [resultados] = await pool.query('SELECT * FROM cadastro WHERE email = ?', [email]); 
        
        
        if (resultados.length === 0) {
            
            return res.status(401).json({ mensagem: "E-mail ou senha incorretos." }); 
        }
        
        const usuario = resultados[0];
        const senhaDoBanco = usuario.senha; 
        
        // 3. Criar o hash da senha digitada
        const hashSenhaInput = crypto.createHash("sha256").update(senha).digest("hex");

        // 4. Comparar os dois hashes
        if (hashSenhaInput === senhaDoBanco) { 
            return res.status(200).json({ mensagem: "Login efetuado com sucesso!" });
        } else {
            return res.status(401).json({ mensagem: "E-mail ou senha incorretos." });
        }

    } catch (error) {
        console.error('ERRO NO LOGIN:', error);
        res.status(500).json({ mensagem: "Erro interno do servidor." });
    }
}); // FIM DA ROTA /login





