//cmd line
//npm init
//npm install express mongoose body-parser cors --save
//npm i nodemon -g
//npm i mongoose //refer
//npm start
//npm install express mongoose express-session bcrypt
//react cmd 
//
//npm install react-axios
//npm install react-router-dom@latest
//npm install multer


const express = require('express');
const session = require('express-session');
const route = express.Router();
const cors = require("cors");
const mongoose = require('mongoose');
const app = express();
const port = 4001;
//const multer = require("multer");
const bodyParser = require("body-parser");
bodyParser.urlencoded()
route.use(bodyParser.json());
route.use(bodyParser.urlencoded({ extended: true }));
const bcrypt = require('bcrypt');

// Middleware
app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// MongoDB Connection URI
const uri = 'mongodb://127.0.0.1:27017/intech_erp';

const crypto = require('crypto');
const secret_code = crypto.randomBytes(64).toString('hex');
console.log(secret_code);

app.use(session({
    secret: secret_code,
    resave: false,
    saveUninitialized: true
}));

// Connect to MongoDB
mongoose.connect(uri, { useNewUrlParser: true, useUnifiedTopology: true })
    .then(() => {
        console.log('Connected to MongoDB');
    })
    .catch((error) => {
        console.error('Error connecting to MongoDB:', error);
    });




// Define mongoose schema and model
const RegisterSchema = new mongoose.Schema({
    // Define schema fields here
    name: {
        type: String,
        required: true
    },
    password: {
        type: String,
        required: true
    },
    email: {
        type: String,
        required: true
    },
    status: { type: Number, default: 1 }//,
    // file: {
    //     type: String
    // } 
},{
    versionKey: false,
});

const Register = mongoose.model('logins', RegisterSchema);


 // Middleware for login validation
 const validateLogin = async (req, res, next) => {
    const { name, password } = req.body;
  
    try {
        // Find the user by username
        const user = await Register.findOne({ name });
        if (!user) {
            return res.status(401).json({ error: 'Invalid username' });
        }

        // Compare the provided password with the hashed password stored in the database
        const passwordMatch = await bcrypt.compare(password, user.password);
        if (!passwordMatch) {
            return res.status(401).json({ error: 'Invalid username or password' });
        }
  
        next(); // Proceed to the next middleware
    } catch (error) {
        console.error('Error during login validation:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
};

// Route for user login
app.post('/login', validateLogin, (req, res) => {
    const { name } = req.body; // Assuming you're sending the username along with the login request
    req.session.userId = name; 
    console.log("User ID in session:", req.session.userId);
    if (req.session.userId) {
      
        res.status(201).json({ userId: req.session.userId, message: 'Login successful' });
    } else {
        // User is not logged in
        res.status(401).json({ error: 'Unauthorized' });
    }

    //res.status(201).json({ message: 'Login successful' });
});






app.get('/logout', (req, res) => {
    // Check if the user is logged in
    if (req.session.userId) {
        // Destroy session on logout
        req.session.destroy((err) => {
            if (err) {
                console.error('Error logging out:', err);
                res.status(500).json({ error: 'Internal Server Error' });
            } else {
                res.send('Logged out successfully');
            }
        });
    } else {
        // If the user is not logged in, simply send a response indicating that they are already logged out
        res.send('Already logged out');
    }
});


// Route to handle GET request
app.get('/fetch', async (req, res) => {
    try {
        // Query the collection
        const documents = await Register.find({status:1});

        // Respond with the documents
        res.json({ documents , msg:'Get Register list'});
    } catch (error) {
        console.log('Error querying MongoDB:', error);
        res.status(500).send('Internal Server Error');
    }
});

app.get('/fetch/:id', async (req, res) => {
    try {
        const { id } = req.params;

        const documents = await Register.findOne({ _id: id }).select('-password');//.select('-password');

        // Respond with the documents
        res.json({ documents , msg:'Get data'});

    } catch (error) {
        console.log('Error data not fetched:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

app.put('/delete/:id', async (req, res) => {
    try {
        const { id } = req.params;
        let { status } = req.body;
        //set it to 0
        if (status = 1) {
            status = 0;
        }

        const updatedRegister = await Register.findByIdAndUpdate(id, { status }, { new: true });

        if (!updatedRegister) {
            return res.status(404).json({ error: 'Register not found' });
        }

        res.json({ message: 'Deleted successfully', Register: updatedRegister });
    } catch (error) {
        console.log('Error updating Register:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});




const validateUserData = (req, res, next) => {
    const { name, password, email } = req.body;
    
    // Check if required fields are present
    if (!name || !password || !email) {
        return res.status(400).json({ error: 'Username, password, and email are required fields' });
    }

    // Check if email is in valid format
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
        return res.status(400).json({ error: 'Invalid email format' });
    }

    // Check if password length is exactly 5 characters
    if (password.length !== 5) {
        return res.status(400).json({ error: 'Password must be exactly 5 characters' });
    }

    //  // Check if file is provided
    //  if (!file) {
    //     return res.status(400).json({ error: 'File upload is required' });
    // }


    next(); // Proceed to the next middleware
};

app.use(validateUserData);

// Set up multer for file upload
// const upload = multer({ 
//     storage: multer.diskStorage({
//         destination: function (req, file, cb) {
//             cb(null, 'uploads/') // Specify the directory where uploaded files should be stored
//         },
//         filename: function (req, file, cb) {
//             cb(null, Date.now() + '-' + file.originalname) // Specify a unique filename for the uploaded file
//         }
//     }),
//     fileFilter: function (req, file, cb) {
//         // Validate file type
//         if (!file.originalname.match(/\.(jpg|jpeg|png)$/)) {
//             return cb(new Error('Only image files are allowed!'), false);
//         }
//         cb(null, true);
//     },
//     limits: {
//         fileSize: 1024 * 1024 * 5 // Limit file size to 5 MB
//     }
// });

app.put('/update/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const { name, password, email } = req.body;

        // Check if password is provided and hash it
        let hashedPassword = password; // Default to the provided password if not changed
        if (password) {
            hashedPassword = await bcrypt.hash(password, 10); // Hash the provided password
        }

        const updatedUser = await Register.findByIdAndUpdate(id, { name, password: hashedPassword, email }, { new: true });

        if (!updatedUser) {
            return res.status(404).json({ error: 'Data not found' });
        }

        res.json({ message: 'Updated successfully', user: updatedUser });
    } catch (error) {
        console.log('Error updating user:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});




app.post('/insert', async (req, res) => {//, upload.single('file')
    try {
        // Extract data from the request body
        const { name, password, email } = req.body;
/*
        let filePath = null;
        if (req.file) {
            filePath = req.file.filename; // Get the filename from req.file
        }*/

        // Hash the password
        const hashedPassword = await bcrypt.hash(password, 10); // Salt rounds: 10

        // Create a new Register document with the hashed password
        const newRegister = new Register({ name, password: hashedPassword, email});//, file: filePath 
        // if (req.file) {
        //     newRegister.filePath = req.file.path; // Assuming Register schema has a field 'filePath' to store the file path
        // }
        // Save the document to the database
        await newRegister.save();

        res.status(201).json({ newRegister, msg: 'Register Created' }); // Send the inserted document as JSON response
    } catch (error) {
        console.error('Error inserting data into Register collection:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});


/*
app.get('/insert',async(req,res) => {   
    const result = await Register.find({name:"sathya"})
    if(result) {
        res.json(result)
    }else {
        res.send("no data") 
    }
    
})*/





// Start the server
app.listen(port, () => {
    console.log(`Server listening at http://localhost:${port}`);
});