const express = require('express')
const bcrypt = require('bcryptjs')
const mongoose = require('mongoose')
const jwt = require('jsonwebtoken')
const cors = require('cors')
require('dotenv').config()

const app = express();

app.use(express.json());
app.use(cors());


//database
const userSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true, lowercase: true, trim: true },
    password: { type: String, required: true },
    createdAt: { type: Date, default: Date.now }
})

const User = mongoose.model('User', userSchema);

//Todo model
const todoSchema = new mongoose.Schema({
  title: { type: String, required: true },
  description: { type: String },
  completed: { type: Boolean, default: false },
  priority: {
    type: String,
    enum: ["low", "medium", "high"],
    default: "medium",
  },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now },
});

const Todo = mongoose.model('Todo', todoSchema)


const authMiddleware = async (req, res, next)=>{
  try {
    const token = req.header('Authorization')?.replace('Bearer ', '');
    
    if (!token) {
      return res.status(401).json({ message: 'No token, authorization denied' });
    }

    // Verify token
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'your-secret-key');
    req.userId = decoded.userId;
    next();
  } catch (error) {
    res.status(401).json({ message: 'Token is not valid' });
  }
  }



  app.post('/api/auth/register', async (req, res)=>{
    try {
      const {name , password, email} = req.body;

      if (!name || !email || !password) {
        return res.status(400).json({ message: 'please provide a valid login details '})
      }
      if (password.length < 6){
        return res.status(400).json({ message: "password must be at least 6 characters"})
      }
      const existingUser = await User.findOne({email})

      if (existingUser){
        return res.status(400).json({ message: 'This user already exist'})
      }

      const salt = await bcrypt.genSalt(10);
      const hashedPassword = await bcrypt.hash(password, salt)

      const user = new User({
        name,
        email,
        password: hashedPassword
      })

      await user.save();

      const token = jwt.sign(
      { userId: user._id },
      process.env.JWT_SECRET || 'your-secret-key',
      { expiresIn: '7d' }
    );
     res.status(201).json({
      message: 'User registered successfully',
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email
      }
    });
  } catch (error) {
    res.status(500).json({ message: 'Server error', error: error.message });
  } 
    
  })

  app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ message: 'Please provide email and password' });
    }

    const user = await User.findOne({email})
    if (!user){
      return res.status(400).json({ message: `user doesn't exist`})
    }

    const isMatch = await bcrypt.compare(password, user.password)

    if(!isMatch){
      return res.status(400).json({ message: 'Invalid credentials' });
    }

    const token = jwt.sign(
      { userId: user._id },
      process.env.JWT_SECRET || 'your-secret-key',
      { expiresIn: '7d' }
    );

    res.json({
      message: 'Login successful',
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email
      }
    });
  } catch (error) {
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});


app.get('/api/auth/me', authMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.userId).select('-password');
    res.json({ user });
  } catch (error) {
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

app.get('/api/todos', authMiddleware, async (req, res) => {
  try {
    const { completed, priority } = req.query;
    
    // Build filter
    const filter = { userId: req.userId };
    if (completed !== undefined) {
      filter.completed = completed === 'true';
    }
    if (priority) {
      filter.priority = priority;
    }

    const todos = await Todo.find(filter).sort({ createdAt: -1 });
    res.json({ count: todos.length, todos });
  } catch (error) {
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

// Get single todo by ID
app.get('/api/todos/:id', authMiddleware, async (req, res) => {
  try {
    const todo = await Todo.findOne({ _id: req.params.id, userId: req.userId });
    
    if (!todo) {
      return res.status(404).json({ message: 'Todo not found' });
    }

    res.json({ todo });
  } catch (error) {
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

// Create new todo
app.post('/api/todos', authMiddleware, async (req, res) => {
  try {
    const { title, description, priority } = req.body;

    // Validation
    if (!title) {
      return res.status(400).json({ message: 'Title is required' });
    }

    const todo = new Todo({
      title,
      description,
      priority: priority || 'medium',
      userId: req.userId
    });

    await todo.save();
    res.status(201).json({ message: 'Todo created successfully', todo });
  } catch (error) {
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

// Update todo
app.put('/api/todos/:id', authMiddleware, async (req, res) => {
  try {
    const { title, description, completed, priority } = req.body;

    const todo = await Todo.findOne({ _id: req.params.id, userId: req.userId });
    
    if (!todo) {
      return res.status(404).json({ message: 'Todo not found' });
    }

    // Update fields
    if (title !== undefined) todo.title = title;
    if (description !== undefined) todo.description = description;
    if (completed !== undefined) todo.completed = completed;
    if (priority !== undefined) todo.priority = priority;
    todo.updatedAt = Date.now();

    await todo.save();
    res.json({ message: 'Todo updated successfully', todo });
  } catch (error) {
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

// Delete todo
app.delete('/api/todos/:id', authMiddleware, async (req, res) => {
  try {
    const todo = await Todo.findOneAndDelete({ _id: req.params.id, userId: req.userId });
    
    if (!todo) {
      return res.status(404).json({ message: 'Todo not found' });
    }

    res.json({ message: 'Todo deleted successfully' });
  } catch (error) {
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

// Toggle todo completion status
app.patch('/api/todos/:id/toggle', authMiddleware, async (req, res) => {
  try {
    const todo = await Todo.findOne({ _id: req.params.id, userId: req.userId });
    
    if (!todo) {
      return res.status(404).json({ message: 'Todo not found' });
    }

    todo.completed = !todo.completed;
    todo.updatedAt = Date.now();
    await todo.save();

    res.json({ message: 'Todo status updated', todo });
  } catch (error) {
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

// ==========================================
// DATABASE CONNECTION & SERVER START
// ==========================================
const PORT = process.env.PORT || 5000;
const MONGO_URI = process.env.MONGO_URI || 'mongodb://localhost:27017/todo-app';

mongoose.connect(MONGO_URI)
  .then(() => {
    console.log('✅ Connected to MongoDB');
    app.listen(PORT, () => {
      console.log(`🚀 Server running on port ${PORT}`);
      console.log(`\n📝 API Endpoints:`);
      console.log(`   POST   /api/auth/register - Register new user`);
      console.log(`   POST   /api/auth/login - Login user`);
      console.log(`   GET    /api/auth/me - Get current user`);
      console.log(`   GET    /api/todos - Get all todos`);
      console.log(`   GET    /api/todos/:id - Get single todo`);
      console.log(`   POST   /api/todos - Create new todo`);
      console.log(`   PUT    /api/todos/:id - Update todo`);
      console.log(`   DELETE /api/todos/:id - Delete todo`);
      console.log(`   PATCH  /api/todos/:id/toggle - Toggle completion\n`);
    });
  })
  .catch((error) => {
    console.error('❌ MongoDB connection error:', error.message);
  });