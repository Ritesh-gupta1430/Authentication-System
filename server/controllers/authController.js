import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import userModel from '../models/userModel.js';
import transporter from '../config/nodemailer.js';
import { EMAIL_VERIFY_TEMPLATE, PASSWORD_RESET_TEMPLATE } from '../config/emailTemplates.js';

export const register = async (req, res) => {
    
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
        return res.json({ success: false, message: 'All fields are required.' });
    }

    try {

        const existingUser = await userModel.findOne({ email });

        if (existingUser) {
            return res.json({ success: false, message: 'User already exists.' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        
        const user = new userModel({ name, email, password: hashedPassword });
        await user.save();

        const token = jwt.sign({id: user._id}, process.env.JWT_SECRET, { expiresIn: '7d' });

        res.cookie('token', token, { 
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict',
            maxAge: 7 * 24 * 60 * 60 * 1000 
        });

        // Send welcome email
        const mailOptions = {
            from: process.env.SENDER_EMAIL,
            to: email,
            subject: 'Welcome to Our Service',
            text: `Hello ${name},\n\nThank you for registering!. We're excited to have you on board.\n\nBest regards,\nThe Team`,
        };

        await transporter.sendMail(mailOptions);

        return res.json({ success: true, message: 'User registered successfully.' });

    } catch (error) {
        return res.json({ success: false, message: error.message });
    }
}

export const login = async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.json({ success: false, message: 'All fields are required.' });
    }

    try {
        
        const user = await userModel.findOne({ email });

        if (!user) {
            return res.json({ success: false, message: 'Invalid email.' });
        }

        const isMatch = await bcrypt.compare(password, user.password);

        if (!isMatch) {
            return res.json({ success: false, message: 'Invalid password.' });
        }
        const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '7d' });

        res.cookie('token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict',
            maxAge: 7 * 24 * 60 * 60 * 1000
        });

        return res.json({ success: true, message: 'Logged in successfully.' });

    } catch (error) {
        return res.json({ success: false, message: error.message });
    }
}

export const logout = (req, res) => {
    try {
        res.clearCookie('token', {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',  
            sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict',
        });

        return res.json({ success: true, message: 'Logged out successfully.' });

    } catch (error) {
        return res.json({ success: false, message: error.message });
    }
}

// send verification otp to user's email
export const sendVerifyOtp = async (req, res) => {
    try {
        
        const {userId} = req.body;

        const user = await userModel.findById(userId);

        if(user.isAccountVerified) {
            return res.json({ success: false, message: 'Account is already verified.' });
        }

        const otp = String(Math.floor(100000 + Math.random() * 900000));

        user.verifyOpt = otp;
        user.verifyOptExpireAt = Date.now() + 24 * 60 * 60 * 1000; // 24 hours from now

        await user.save();

        const mailOptions = {
            from: process.env.SENDER_EMAIL,
            to: user.email,
            subject: 'Account Verification OTP',
            // text: `Hello ${user.name},\n\nYour OTP for account verification is: ${otp}\nThis OTP is valid for 24 hours.\n\nBest regards,\nThe Team`,
            html: EMAIL_VERIFY_TEMPLATE.replace('{{email}}', user.email).replace('{{otp}}', otp),
        }
        await transporter.sendMail(mailOptions);

        return res.json({ success: true, message: 'OTP sent successfully.' });

    } catch (error) {
        res.json({ success: false, message: error.message });
    }
}

// verify user's email using otp
export const verifyEmail = async (req, res) => {
    const { userId, otp } = req.body;

    if (!userId || !otp) {
        return res.json({ success: false, message: 'Missing Details.' });
    }
    try {
        const user = await userModel.findById(userId);
        
        if (!user) {
            return res.json({ success: false, message: 'User not found.' });
        }

        if(user.verifyOpt === '' || user.verifyOpt !== otp) {
            return res.json({ success: false, message: 'Invalid OTP.' });
        }

        if (user.verifyOptExpireAt < Date.now()) {
            return res.json({ success: false, message: 'OTP has expired.' });
        }

        user.isAccountVerified = true;
        user.verifyOpt = '';
        user.verifyOptExpireAt = 0;

        await user.save();
        return res.json({ success: true, message: 'Email verified successfully.' });

    } catch (error) {
        return res.json({ success: false, message: error.message });
    }
}

// check if user is authenticated
export const isAuthenticated = (req, res) => {
    try {
        return res.json({ success: true, message: 'User is authenticated.' });
    } catch (error) {
        return res.json({ success: false, message: error.message });
    }
}

// send password reset otp to user's email
export const sendResetOtp = async (req, res) => {
    const { email } = req.body;

    if (!email) {
        return res.json({ success: false, message: 'Email is required.' });
    }

    try {

        const user = await userModel.findOne({ email });

        if (!user) {
            return res.json({ success: false, message: 'User not found.' });
        }

        const otp = String(Math.floor(100000 + Math.random() * 900000));

        user.resetOtp = otp;
        user.resetOtpExpireAt = Date.now() + 15 * 60 * 1000; // 15 minutes from now

        await user.save();

        const mailOptions = {
            from: process.env.SENDER_EMAIL,
            to: user.email,
            subject: 'Password Reset OTP',
            // text: `Hello ${user.name},\n\nYour OTP for password reset is: ${otp}\nThis OTP is valid for 15 minutes.\n\nBest regards,\nThe Team`,
            html: PASSWORD_RESET_TEMPLATE.replace('{{email}}', user.email).replace('{{otp}}', otp)
        }
        await transporter.sendMail(mailOptions);

        return res.json({ success: true, message: 'OTP sent successfully.' });

    } catch (error) {
        return res.json({ success: false, message: error.message });
    }
}

// reset user password
export const resetPassword = async (req, res) => {
    const { email, otp, newPassword } = req.body;

    if (!email || !otp || !newPassword) {
        return res.json({ success: false, message: 'Email, OTP, and new password are required.' });
    }

    try {

        const user = await userModel.findOne({ email });
        if (!user) {
            return res.json({ success: false, message: 'User not found.' });
        }

        if (user.resetOtp === '' || user.resetOtp !== otp) {
            return res.json({ success: false, message: 'Invalid OTP.' });
        }

        if (user.resetOtpExpireAt < Date.now()) {
            return res.json({ success: false, message: 'OTP has expired.' });
        }

        const hashedPassword = await bcrypt.hash(newPassword, 10);

        user.password = hashedPassword;
        user.resetOpt = '';
        user.resetOptExpireAt = 0;

        await user.save();

        return res.json({ success: true, message: 'Password has been reset successfully.' });

    } catch (error) {
        return res.json({ success: false, message: error.message });
    }
}