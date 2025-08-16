import User from "../models/User.js";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";

// Generate JWT Token
const generateToken = (userId) => {
  if (!process.env.JWT_SECRET) {
    throw new Error('JWT_SECRET is not defined in environment variables');
  }
  return jwt.sign({ userId }, process.env.JWT_SECRET, { 
    expiresIn: "7d" 
  });
};

// @desc    Register new user
// @route   POST /api/auth/signup
// @access  Public
export const signup = async (req, res) => {
  try {
    const { email, password, name } = req.body;

    // Validate required fields
    if (!email || !password || !name) {
      return res.status(400).json({ 
        message: "Email, password, and name are required" 
      });
    }

    // Validate password length
    if (password.length < 6) {
      return res.status(400).json({ 
        message: "Password must be at least 6 characters long" 
      });
    }

    // Check if user already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ 
        message: "User with this email already exists" 
      });
    }

    // Hash password
    const salt = await bcrypt.genSalt(10);
    const passwordHash = await bcrypt.hash(password, salt);

    // Create new user
    const user = new User({
      email,
      passwordHash,
      name
    });

    await user.save();

    // Generate token
    const token = generateToken(user._id);

    res.status(201).json({
      success: true,
      message: "User registered successfully",
      token,
      user: {
        id: user._id,
        email: user.email,
        name: user.name,
        phone: user.phone || '',
        avatarUrl: user.avatarUrl || ''
      }
    });

  } catch (error) {
    console.error("Signup error:", error);
    console.error("Error stack:", error.stack);
    
    // Check for specific error types
    if (error.name === 'ValidationError') {
      return res.status(400).json({ 
        message: "Validation error: " + Object.values(error.errors).map(e => e.message).join(', ')
      });
    }
    
    if (error.code === 11000) {
      return res.status(400).json({ 
        message: "User with this email already exists" 
      });
    }
    
    res.status(500).json({ 
      message: "Server error during registration: " + error.message
    });
  }
};

// @desc    Login user
// @route   POST /api/auth/login
// @access  Public
export const login = async (req, res) => {
  try {
    const { email, password } = req.body;

    // Validate required fields
    if (!email || !password) {
      return res.status(400).json({ 
        message: "Email and password are required" 
      });
    }

    // Find user by email
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ 
        message: "Invalid email or password" 
      });
    }

    // Check password
    const isPasswordValid = await user.comparePassword(password);
    if (!isPasswordValid) {
      return res.status(401).json({ 
        message: "Invalid email or password" 
      });
    }

    // Generate token
    const token = generateToken(user._id);

    res.json({
      success: true,
      message: "Login successful",
      token,
      user: {
        id: user._id,
        email: user.email,
        name: user.name,
        phone: user.phone || '',
        avatarUrl: user.avatarUrl || ''
      }
    });

  } catch (error) {
    console.error("Login error:", error);
    console.error("Error stack:", error.stack);
    res.status(500).json({ 
      message: "Server error during login: " + error.message
    });
  }
};

// @desc    Get current user
// @route   GET /api/auth/me
// @access  Private
export const getCurrentUser = async (req, res) => {
  try {
    const user = await User.findById(req.user._id).select("-passwordHash");
    
    if (!user) {
      return res.status(404).json({ 
        message: "User not found" 
      });
    }

    res.json({
      success: true,
      user: {
        id: user._id,
        email: user.email,
        name: user.name,
        phone: user.phone || '',
        avatarUrl: user.avatarUrl || '',
        createdAt: user.createdAt
      }
    });
  } catch (error) {
    console.error("Get current user error:", error);
    res.status(500).json({ 
      message: "Server error: " + error.message
    });
  }
};

// @desc    Verify token
// @route   POST /api/auth/verify
// @access  Public
export const verifyToken = async (req, res) => {
  try {
    const { token } = req.body;

    if (!token) {
      return res.status(400).json({ 
        message: "Token is required" 
      });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(decoded.userId).select("-passwordHash");

    if (!user) {
      return res.status(401).json({ 
        message: "Invalid token" 
      });
    }

    res.json({
      success: true,
      user: {
        id: user._id,
        email: user.email,
        name: user.name,
        phone: user.phone || '',
        avatarUrl: user.avatarUrl || ''
      }
    });

  } catch (error) {
    console.error("Token verification error:", error);
    res.status(401).json({ 
      message: "Invalid token" 
    });
  }
}; 