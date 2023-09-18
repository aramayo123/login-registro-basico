//1 - invocamos a express
const express = require('express');
const app = express();

//2- seteeamos urlencoded para capturar los datos del formulario
app.use(express.urlencoded({extended:false}));
app.use(express.json());

//3 - invocamos a dotenv
const dotenv = require('dotenv');
dotenv.config({path:'./env/.env'});

//4 - el directorio public
app.use('/resources',express.static('public'));
app.use('/resources',express.static(__dirname + '/public'));

//5 - Establecemos el motor de plantillas
app.set('view engine','ejs');

//6 -Invocamos a bcrypt ( es para encriptar las contraseñas )
const bcrypt = require('bcryptjs');

//7- variables de session
const session = require('express-session');
app.use(session({
	secret: 'secret',
	resave: true,
	saveUninitialized: true
}));

// 8 - Invocamos a la conexion de la DB
const connection = require('./database/db');

//9 - establecemos las rutas
app.get('/login',(req, res)=>{
    res.render('login');
})

app.get('/register',(req, res)=>{
    res.render('register');
})


//10 - Método para la REGISTRACIÓN
app.post('/register', async (req, res)=>{
	const user = req.body.user;
	const name = req.body.name;
	const email = req.body.email;
	const pass = req.body.pass;
	const pass2 = req.body.pass2;
	if(user != '' && name != '' && email != '' && pass != '' && pass2 != ''){
		if(pass == pass2){
			let passwordHash = await bcrypt.hash(pass, 8);
			connection.query('SELECT * FROM usuarios WHERE usuario = ?', [user], async (error, results, fields)=> {
				if( results.length == 0){
					connection.query('SELECT * FROM usuarios WHERE email = ?', [email], async (error, results, fields)=> {
						if( results.length == 0){
							connection.query('INSERT INTO usuarios SET ?',{nombre:name, usuario:user, email:email, password:passwordHash}, async (error, results)=>{
								if(error){
									console.log(error);
								}else{            
									res.render('register', {
										alert: true,
										alertTitle: "Registration",
										alertMessage: "¡Successful Registration!",
										alertIcon:'success',
										showConfirmButton: false,
										timer: 1500,
										ruta: 'login'
									});
									//res.redirect('/');         
								}
							});
						}else{
							res.render('register', {
								alert: true,
								alertTitle: "Error",
								alertMessage: "¡El email ya existe!",
								alertIcon:'error',
								showConfirmButton: true,
								timer: false,
								ruta: ''
							});
						}
					});
				}else{
					res.render('register', {
						alert: true,
						alertTitle: "Error",
						alertMessage: "¡El usuario ya existe!",
						alertIcon:'error',
						showConfirmButton: true,
						timer: false,
						ruta: ''
					});
				}
			});
		}else{
			res.render('register', {
				alert: true,
				alertTitle: "Error",
				alertMessage: "¡Las contraseñas no coinciden!",
				alertIcon:'error',
				showConfirmButton: true,
				timer: false,
				ruta: ''
			});
		}
	}else{
		res.render('register', {
			alert: true,
			alertTitle: "Error",
			alertMessage: "¡Debes rellenar todos los campos!",
			alertIcon:'error',
			showConfirmButton: true,
			timer: false,
			ruta: ''
		});
	}
})



//11 - Metodo para la autenticacion
app.post('/auth', async (req, res)=> {
	const user = req.body.user;
	const pass = req.body.pass;    
    let passwordHash = await bcrypt.hash(pass, 8);
	if (user && pass) {
		connection.query('SELECT * FROM usuarios WHERE usuario = ?', [user], async (error, results, fields)=> {
			if( results.length == 0 || !(await bcrypt.compare(pass, results[0].password)) ) {    
				res.render('login', {
                        alert: true,
                        alertTitle: "Error",
                        alertMessage: "USUARIO y/o PASSWORD incorrectas",
                        alertIcon:'error',
                        showConfirmButton: true,
                        timer: false,
                        ruta: 'login'    
                    });
				
				//Mensaje simple y poco vistoso
                //res.send('Incorrect Username and/or Password!');				
			} else {         
				//creamos una var de session y le asignamos true si INICIO SESSION       
				req.session.loggedin = true;                
				req.session.name = results[0].nombre;
				res.render('login', {
					alert: true,
					alertTitle: "Conexión exitosa",
					alertMessage: "¡LOGIN CORRECTO!",
					alertIcon:'success',
					showConfirmButton: false,
					timer: 1500,
					ruta: ''
				});        			
			}			
			res.end();
		});
	} else {	
		res.send('Please enter user and Password!');
		res.end();
	}
});

//12 - Método para controlar que está auth en todas las páginas
app.get('/', (req, res)=> {
	if (req.session.loggedin) {
		res.render('index',{
			login: true,
			name: req.session.name	
		});		
	} else {
		res.render('login',{
			login:false,
			name:'Debe iniciar sesión',			
		});				
	}
	res.end();
});


//función para limpiar la caché luego del logout
app.use(function(req, res, next) {
    if (!req.user)
        res.header('Cache-Control', 'private, no-cache, no-store, must-revalidate');
    next();
});

 //Logout
//Destruye la sesión.
app.get('/logout', function (req, res) {
	req.session.destroy(() => {
	  res.redirect('/') // siempre se ejecutará después de que se destruya la sesión
	})
});


app.listen(3000, (req, res)=>{
    console.log('SERVER RUNNING IN http://localhost:3000');
});