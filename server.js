const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcrypt');
const rateLimit = require('express-rate-limit');
const { body, validationResult, check } = require('express-validator');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const app = express();
const path = require('path');
const Transport = require("nodemailer-brevo-transport");

app.use(express.json());
app.set('trust proxy', true);
app.use(cors({
    origin: '*', 
    methods: ['GET', 'POST', 'PATCH', 'DELETE', 'PUT'], 
    allowedHeaders: ['Content-Type', 'Authorization'] 
}));

app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

mongoose.connect('mongodb://localhost:27017/platform', {
    useNewUrlParser: true,
    useUnifiedTopology: true,
});

const bonusSchema = new mongoose.Schema({
    title: { type: String, required: true },
    points: { type: Number, required: true },
});

const Bonus = mongoose.model('Bonus', bonusSchema);

const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    wallet: { type: String },
    FullName: { type: String, required: true },
    verified: { type: Boolean, default: true },
    verificationToken: { type: String },
    registrationDate: { type: Date, default: Date.now },
    isPrivate: { type: Boolean, default: false },
    bonuses: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Bonus' }],
    points: { type: Number, default: 0 },
    title: { type: String, default: 'Your Title' },
    description: { type: String, default: 'Set your description here!' },
    skills: [{ type: String }],
    country: { type: String },
    kind: {type: Number, default: 0},
    referrer: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    tasks: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Task' }],
    resetPasswordToken: String,
    resetPasswordExpires: Date,
});

const User = mongoose.model('User', userSchema);


const jobPostSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    jobTitle: { type: String, required: true },
    jobType: { type: String, required: true },
    jobTiming: { type: String, required: true },
    jobRequirements: { type: String, required: true },
    salaryType: { type: String, required: true },
    salaryMin: { type: Number, required: true },
    salaryMax: { type: Number, required: true },
    salaryRate: { type: String, required: true },
    supplementalPay: { type: String, required: false },
    benefits: { type: String, required: false },
    language: { type: String, required: true },
    hiringAmount: { type: Number, required: true },
    hiringUrgency: { type: String, required: true },
    creationDate: { type: Date, default: Date.now },
  });
  
  const JobPost = mongoose.model('JobPost', jobPostSchema);

  const taskSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    title: { type: String, required: true },
    category: { type: String, required: true },
    subCategory: { type: String },
    projectAttributes: [{ type: String }],
    keywords: [{ type: String }],
    pricingTitle: { type: String },
    description: { type: String, required: true },
    deliveryDays: { type: Number, required: true },
    numberOfPagesOrScreens: { type: Number },
    price: { type: Number, required: true },
    serviceOptions: [{ type: String }],
    packageDescription: { type: String },
    question: { type: String },
    images: [{ type: String }],
    externalLink: { type: String },
    socialLinks: [{ type: String }]
  });
  
  const Task = mongoose.model('Task', taskSchema);

const getUserFromToken = (token) => {
    try {
        const decoded = jwt.verify(token, 'secret_key');
        return decoded.id;
    } catch (error) {
        return null;
    }
};

const sanitizeUser = (user) => {
    const sanitizedUser = { ...user.toObject() };
    delete sanitizedUser.password;
    return sanitizedUser;
};


const transporter = nodemailer.createTransport(
  new Transport({ apiKey: "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" })
);


async function sendEmail(to, name, verifyLink) {
    const emailHtml = `
<!DOCTYPE html>
<html lang="en" xmlns:v="urn:schemas-microsoft-com:vml">
<head>
  <meta charset="utf-8">
  <meta name="x-apple-disable-message-reformatting">
  <meta http-equiv="x-ua-compatible" content="ie=edge">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="format-detection" content="telephone=no, date=no, address=no, email=no">
  <meta name="color-scheme" content="light dark">
  <meta name="supported-color-schemes" content="light dark">
  <title>Welcome to Deelance</title>  
  <style>
    .hover-bg-primary-light:hover {
      background-color: #55f3de !important;
    }
    .hover-text-decoration-underline:hover {
      text-decoration: underline;
    }
    @media (max-width: 600px) {
      .sm-w-full {
        width: 100% !important;
      }
      .sm-py-8 {
        padding-top: 32px !important;
        padding-bottom: 32px !important;
      }
      .sm-px-6 {
        padding-left: 24px !important;
        padding-right: 24px !important;
      }
      .sm-leading-8 {
        line-height: 32px !important;
      }
    }
  </style>
</head>
<body style="word-break: break-word; -webkit-font-smoothing: antialiased; margin: 0; width: 100%; background-color: #f8fafc; padding: 0">
  <div style="display: none">
  </div>
  <div role="article" aria-roledescription="email" aria-label="Confirm your email address" lang="en">    
    <table style="width: 100%; font-family: ui-sans-serif, system-ui, -apple-system, 'Segoe UI', sans-serif" cellpadding="0" cellspacing="0" role="presentation">
      <tr>
        <td align="center" style="background-color: #f8fafc">
          <table class="sm-w-full" style="width: 600px" cellpadding="0" cellspacing="0" role="presentation">
            <tr>
              <td class="sm-py-8 sm-px-6" style="padding: 18px; background: #0A0A0B;">
                <h1 style="border: 0; color:#ffffff; max-width: 55%; vertical-align: middle">Deelance</h1>
              </td>
            </tr>
            <tr>
              <td align="center" class="sm-px-6">
                <table style="width: 100%" cellpadding="0" cellspacing="0" role="presentation">
                  <tr>
                    <td class="sm-px-6" style="border-radius: 4px; background-color: #fff; padding: 16px 28px 16px 28px; text-align: left; font-size: 14px; line-height: 24px; color: #334155; box-shadow: 0 1px 2px 0 rgba(0, 0, 0, 0.05)">
                      <p>Hello!</p>
                      <p>Thanks for signing up for Deelance.</p>
                      <p>Please click the link below to verify your account:</p>
                      <div style="line-height: 100%; margin-bottom: 20px; text-align: center;">
                      <a href="${verifyLink}" style="background-color: #864DD2; color: #fff; padding: 10px 20px; text-decoration: none; border-radius: 5px; display: inline-block;">Verify email address</a>
                      </div>
                      <table style="width: 100%" cellpadding="0" cellspacing="0" role="presentation">
                        <tr>
                          <td>
                            <div>
                              <p style="margin-bottom:0;">Cheers,</p>
                              <p style="margin-top:0;">The Deelance Team</p>
                            </div>
                          </td>
                        </tr>
                      </table>
                    </td>
                  </tr>
                  <tr>
                    <td style="height: 48px"></td>
                  </tr>
                </table>
              </td>
            </tr>
          </table>
        </td>
      </tr>
    </table>
  </div>
</body>
</html>
`;

    const mailOptions = {
      from: 'noreply@deelance.com',
      to: to,
      subject: 'Verify your Email! - Deelance',
      html: emailHtml
    };

    try {
      const result = await transporter.sendMail(mailOptions);
      console.log('Email inviata con successo:', result);
    } catch (error) {
      console.error('Errore nell\'invio dell\'email:', error);
    }
}



const limiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 154500,
});

app.use(limiter);

const authenticate = async (req, res, next) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
        return res.status(401).send('No token provided');
    }

    const userId = getUserFromToken(token);
    if (!userId) {
        return res.status(401).send('Invalid token');
    }

    req.userId = userId;
    next();
};



const storage = multer.diskStorage({
    destination: (req, file, cb) => {
      cb(null, 'uploads/')
    },
    filename: (req, file, cb) => {
      // Estrai l'estensione del file originale
      const fileExt = file.originalname.split('.').pop();
      // Usa l'ID utente dal token di autenticazione per il nome del file
      cb(null, req.userId + '.' + fileExt);
    }
  })
  
  const upload = multer({ storage: storage });
  
  app.post('/user/avatar', authenticate, upload.single('avatar'), async (req, res) => {
      // Il userId viene ora prelevato dal token di autenticazione
      const userId = req.userId;
  
      if (!req.file) {
          return res.status(400).send('No file uploaded');
      }
  
      try {
          const user = await User.findById(userId);
          if (!user) {
              return res.status(404).send('User not found');
          }
  
          // Il percorso dell'avatar sarà sempre basato sull'userId, quindi non c'è bisogno di aggiornarlo nel DB
          const avatarUrl = `/uploads/${userId}.${req.file.filename.split('.').pop()}`;
          res.status(200).json({ avatar: avatarUrl });
      } catch (error) {
          console.error(error);
          res.status(500).send('Server error');
      }
  });
  
app.post('/create-task', authenticate, async (req, res) => {
  try {
    const task = new Task({ ...req.body, userId: req.userId });
    await task.save();
    res.status(201).json(task);
  } catch (error) {
    console.error(error);
    res.status(500).send('Server error');
  }
});


app.get('/task/:taskId', async (req, res) => {
    try {
      const task = await Task.findById(req.params.taskId).populate('userId', 'username email FullName');
      if (!task) {
        return res.status(404).send('Task not found');
      }
      res.json(task);
    } catch (error) {
      console.error(error);
      res.status(500).send('Server error');
    }
  });

  async function sendPasswordResetEmail(to, resetLink) {
    const emailHtml = `
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="utf-8">
      <meta name="x-apple-disable-message-reformatting">
      <meta http-equiv="x-ua-compatible" content="ie=edge">
      <meta name="viewport" content="width=device-width, initial-scale=1">
      <meta name="format-detection" content="telephone=no, date=no, address=no, email=no">
      <meta name="color-scheme" content="light dark">
      <meta name="supported-color-schemes" content="light dark">
      <title>Reset Password - Deelance</title>
      <style>
        .hover-bg-primary-light:hover {
          background-color: #55f3de !important;
        }
        .hover-text-decoration-underline:hover {
          text-decoration: underline;
        }
        @media (max-width: 600px) {
          .sm-w-full {
            width: 100% !important;
          }
          .sm-py-8 {
            padding-top: 32px !important;
            padding-bottom: 32px !important;
          }
          .sm-px-6 {
            padding-left: 24px !important;
            padding-right: 24px !important;
          }
          .sm-leading-8 {
            line-height: 32px !important;
          }
        }
      </style>
    </head>
    <body style="word-break: break-word; -webkit-font-smoothing: antialiased; margin: 0; width: 100%; background-color: #f8fafc; padding: 0">
      <div role="article" aria-roledescription="email" lang="en">
        <table style="width: 100%; font-family: ui-sans-serif, system-ui, -apple-system, 'Segoe UI', sans-serif" cellpadding="0" cellspacing="0" role="presentation">
          <tr>
            <td align="center" style="background-color: #f8fafc">
              <table class="sm-w-full" style="width: 600px" cellpadding="0" cellspacing="0" role="presentation">
                <tr>
                  <td class="sm-py-8 sm-px-6" style="padding: 18px; background: #0A0A0B;">
                    <h1 style="border: 0; color: #ffffff; max-width: 55%; vertical-align: middle">Deelance</h1>
                  </td>
                </tr>
                <tr>
                  <td align="center" class="sm-px-6">
                    <table style="width: 100%" cellpadding="0" cellspacing="0" role="presentation">
                      <tr>
                        <td class="sm-px-6" style="border-radius: 4px; background-color: #fff; padding: 16px 28px 16px 28px; text-align: left; font-size: 14px; line-height: 24px; color: #334155; box-shadow: 0 1px 2px 0 rgba(0, 0, 0, 0.05)">
                          <p>Hello,</p>
                          <p>To reset your password, please click the button below:</p>
                          <div style="line-height: 100%; margin-bottom: 20px; text-align: center;">
                            <a href="${resetLink}" class="hover-bg-primary-light" style="text-decoration: none; display: inline-block; border-radius: 4px; background-color: #864DD2; padding-top: 14px; padding-bottom: 14px; padding-left: 16px; padding-right: 16px; text-align: center; font-size: 14px; font-weight: 600; color: #fff">Reset Password &rarr;</a>
                          </div>
                          <p>Cheers,</p>
                          <p>The Deelance Team</p>
                        </td>
                      </tr>
                      <tr>
                        <td style="height: 48px"></td>
                      </tr>
                    </table>
                  </td>
                </tr>
              </table>
            </td>
          </tr>
        </table>
      </div>
    </body>
    </html>`;

    const mailOptions = {
      from: 'noreply@deelance.com',
      to: to,
      subject: 'Reset Password - Deelance',
      html: emailHtml
    };

    try {
      const result = await transporter.sendMail(mailOptions);
      console.log('Email inviata con successo:', result);
    } catch (error) {
      console.error('Errore nell\'invio dell\'email:', error);
    }
}

app.post('/forgot-password', async (req, res) => {
  const { email } = req.body;
  const user = await User.findOne({ email });

  if (!user) {
      return res.status(404).send('User not found');
  }

  const token = crypto.randomBytes(20).toString('hex');
  user.resetPasswordToken = token;
  user.resetPasswordExpires = Date.now() + 3600000; // 1 hour

  await user.save();

  const resetUrl = `https://app.deelance.com/reset-password/${token}`;
  await sendPasswordResetEmail(user.email, resetUrl);

  res.send('Password reset link sent!');
});



app.post('/reset-password/:token', async (req, res) => {
  const { password } = req.body;
  const { token } = req.params;

  const user = await User.findOne({
      resetPasswordToken: token,
      resetPasswordExpires: { $gt: Date.now() }
  });

  if (!user) {
      return res.status(400).send('Token not valid');
  }

  user.password = await bcrypt.hash(password, 10);
  user.resetPasswordToken = undefined;
  user.resetPasswordExpires = undefined;

  await user.save();

  res.send('Password successfly reset!');
});



  app.get('/tasks', authenticate, async (req, res) => {
    try {
        const tasks = await Task.find({}).populate('userId', 'username email FullName');
        res.json(tasks);
    } catch (error) {
        console.error(error);
        res.status(500).send('Server error');
    }
});


app.get('/profile/:userId', async (req, res) => {
    const { userId } = req.params;

    if (!mongoose.Types.ObjectId.isValid(userId)) {
        return res.status(400).json({ error: 'Invalid user ID' });
    }

    try {
        const user = await User.findById(userId);
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        if (user.isPrivate) {
            const token = req.headers.authorization?.split(' ')[1];
            const userIdFromToken = getUserFromToken(token);

            if (!userIdFromToken || userIdFromToken !== user._id.toString()) {
                return res.status(401).json({ error: 'Unauthorized' });
            }
        }

        res.json({ user: user });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Server error' });
    }
});

app.patch('/user/:userId/visibility', authenticate, async (req, res) => {
    const { userId } = req.params;
    const { isPrivate } = req.body;

    try {
        const user = await User.findById(userId);
        if (!user) {
            console.log('User not found');
            return res.status(404).send('User not found');
        }

        if (user._id.toString() !== req.userId) {
            console.log('Unauthorized');
            return res.status(401).send('Unauthorized');
        }

        user.isPrivate = isPrivate;
        await user.save();

        console.log('Profile visibility updated successfully');
        res.status(200).send('Profile visibility updated successfully');
    } catch (error) {
        console.log('Server error:', error);
        res.status(500).send('Server error');
    }
});

app.post('/post-job', authenticate, async (req, res) => {
    const {
      jobTitle,
      jobType,
      jobTiming,
      jobRequirements,
      salaryType,
      salaryMin,
      salaryMax,
      salaryRate,
      supplementalPay,
      benefits,
      language,
      hiringAmount,
      hiringUrgency
    } = req.body;
  
    const jobPost = new JobPost({
      userId: req.userId, // from authenticate middleware
      jobTitle,
      jobType,
      jobTiming,
      jobRequirements,
      salaryType,
      salaryMin,
      salaryMax,
      salaryRate,
      supplementalPay,
      benefits,
      language,
      hiringAmount,
      hiringUrgency
    });
  
    try {
      await jobPost.save();
      res.status(201).json({ message: 'Job posted successfully', jobId: jobPost._id });
    } catch (error) {
      console.error(error);
      res.status(500).json({ error: 'Error creating job post' });
    }
  });
  
  // Endpoint to get all job posts for a user
  app.get('/user/:userId/job-posts', authenticate, async (req, res) => {
    const { userId } = req.params;
    if (req.userId !== userId) {
      return res.status(401).json({ error: 'Unauthorized' });
    }
  
    try {
      const jobPosts = await JobPost.find({ userId });
      res.json({ jobPosts });
    } catch (error) {
      console.error(error);
      res.status(500).json({ error: 'Error fetching job posts' });
    }
  });
  


const { getCode, getName } = require('country-list');

app.patch('/user/:userId/country', authenticate, async (req, res) => {
    const { userId } = req.params;
    const { country } = req.body;

    // Controlla se il paese fornito è valido
/*     if (!getName(country)) {
        return res.status(400).send('Invalid country name');
    }
 */
    try {
        const user = await User.findById(userId);
        if (!user) {
            console.log('User not found');
            return res.status(404).send('User not found');
        }

        if (user._id.toString() !== req.userId) {
            console.log('Unauthorized');
            return res.status(401).send('Unauthorized');
        }

        user.country = country;
        await user.save();

        console.log('Profile country updated successfully');
        res.status(200).send('Profile country updated successfully');
    } catch (error) {
        console.log('Server error:', error);
        res.status(500).send('Server error');
    }
});


app.patch('/user/:userId/skills', authenticate, async (req, res) => {
    const { userId } = req.params;
    const { skills } = req.body;

    try {
        const user = await User.findById(userId);
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        if (user._id.toString() !== req.userId) {
            return res.status(401).json({ error: 'Unauthorized' });
        }

        user.skills = skills;
        await user.save();

        // Inviare una risposta JSON con i dati aggiornati
        res.status(200).json({ skills: user.skills });
    } catch (error) {
        console.log('Server error:', error);
        // Inviare una risposta JSON con il messaggio di errore
        res.status(500).json({ error: 'Server error' });
    }
});



app.post('/register', [
    body('username').trim().escape().matches(/^[A-Za-z0-9]+$/),
    body('email').trim().isEmail(),
    body('password').isLength({ min: 6 }),
    body('wallet').trim().escape().optional(),
    body('FullName').trim().escape().matches(/^[A-Za-z\s]+$/),
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    const { username, email, password, wallet, FullName, referrer } = req.body;

    // Controlla se l'email esiste già
    const existingEmail = await User.findOne({ email });
    if (existingEmail) {
        return res.status(400).send('Email already exists');
    }

    // Controlla se l'username esiste già
    const existingUserName = await User.findOne({ username });
    if (existingUserName) {
        return res.status(400).send('Username already exists');
    }

    // Controlla se il wallet esiste già e non è vuoto
    if (wallet) {
        const existingWallet = await User.findOne({ wallet });
        if (existingWallet) {
            return res.status(400).send('Wallet Address already exists');
        }
    }

    let referrerUser = null;
    if (referrer) {
        console.log(referrer)
        referrerUser = await User.findById(referrer);
        if (!referrerUser) {
            referrerUser = null;
        }
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const verificationToken = crypto.randomBytes(20).toString('hex');

    const newUser = new User({ 
        username, 
        email, 
        password: hashedPassword, 
        wallet: wallet || '', // Usa stringa vuota se wallet non è fornito
        FullName, 
        verificationToken,
        referrer: referrerUser ? referrerUser._id : null // Salva l'ID del referrer se esiste
    });
    await newUser.save();

    const verificationUrl = `https://app.deelance.com/email-verify?token=${verificationToken}`;
    const emailHtml = `<p>Click here to verify your email: <a href="${verificationUrl}">Verify!</a></p>`;

    try {
        await sendEmail(email, username, verificationUrl);
        console.log('Email sent successfully');
        res.status(201).send('User registered successfully');
    } catch (error) {
        console.error('Failed to send verification email:', error);
        res.status(500).send('Failed to send verification email');
    }
});


app.post('/login', [
    body('email').trim().isEmail().withMessage('Invalid email format'),
    body('password').isLength({ min: 6 }).withMessage('Password must be at least 6 characters long'),
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    const { email, password } = req.body;

    try {
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(400).send('Invalid email or password');
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).send('Invalid email or password');
        }

        if (!user.verified) {
            return res.status(400).send('Please verify your email first');
        }

        const token = jwt.sign({ id: user._id }, 'secret_key', { expiresIn: '7d' });


        res.json({ token });
    } catch (error) {
        console.log(error);
        res.status(500).send('Server error');
    }
});

app.get('/email-verify', [
    check('token')
        .trim()
        .escape()
        .isLength({ min: 1 })
        .withMessage('Token is required'),
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    const { token } = req.query;

    try {
        const user = await User.findOne({ verificationToken: token });
        if (!user) {
            return res.status(400).send('Invalid token');
        }
        user.verified = true;
        user.verificationToken = undefined;
        await user.save();

        if (user.referrer) {
            const referrer = await User.findById(user.referrer);
            if (referrer) {
              referrer.points += 100; 
              await referrer.save();
            }
          }

        res.status(200).send('Email verified successfully');
    } catch (error) {
        console.log(error);
        res.status(500).send('Server error');
    }
});

app.get('/user', authenticate, async (req, res) => {
    try {
        const user = await User.findById(req.userId);
        if (!user) {
            return res.status(404).send('User not found');
        }

        const sanitizedUser = sanitizeUser(user);
        res.json({ user: sanitizedUser });
    } catch (error) {
        console.log(error);
        res.status(500).send('Server error');
    }
});


app.get('/bonuses', authenticate, async (req, res) => {
  try {
      const user = await User.findById(req.userId).populate('bonuses');
      if (!user) {
          return res.status(404).send('User not found');
      }

      const bonuses = await Bonus.find();
      const availableBonuses = bonuses.filter(bonus => !user.bonuses.includes(bonus._id));
      res.json({ bonuses: availableBonuses });
  } catch (error) {
      console.error(error);
      res.status(500).send('Server error');
  }
});


app.patch('/profile', authenticate, async (req, res) => {
    const { title, description } = req.body;

    try {
        const user = await User.findById(req.userId);
        if (!user) {
            return res.status(404).send('User not found');
        }

        user.title = title;
        user.description = description;
        await user.save();

        res.json({ title: user.title, description: user.description });
    } catch (error) {
        console.log(error);
        res.status(500).send('Server error');
    }
});

app.get('/api/jobs', authenticate, async (req, res) => {
    const page = parseInt(req.query.page) || 1; // la pagina corrente, default 1
    const limit = parseInt(req.query.limit) || 10; // il numero di elementi per pagina, default 10
  
    try {
      const jobPosts = await JobPost.find({})
        .populate('userId', 'FullName country')
        .skip((page - 1) * limit)
        .limit(limit);
  
      const count = await JobPost.countDocuments(); // conta il totale dei documenti
  
      res.json({
        totalPages: Math.ceil(count / limit),
        currentPage: page,
        jobPosts,
      });
    } catch (error) {
      console.error(error);
      res.status(500).json({ error: 'Error fetching job posts' });
    }
  });
  
  app.get('/api/jobs/:jobId', async (req, res) => {
    try {
        const jobPost = await JobPost.findById(req.params.jobId)
                                    .populate('userId', 'username email FullName');
        if (!jobPost) {
            return res.status(404).send('Job not found');
        }
        res.json(jobPost);
    } catch (err) {
        console.error(err);
        res.status(500).send('Server error');
    }
});

  app.patch('/user/:userId/update-kind', authenticate, async (req, res) => {
    const { userId } = req.params;
    const { kind } = req.body;
    console.log('Updating kind for user:', userId, 'to:', kind); 
    try {
      const user = await User.findById(userId);
      if (!user) {
        return res.status(404).send('User not found');
      }
  
      if (user._id.toString() !== req.userId) {
        return res.status(401).send('Unauthorized');
      }
  
      user.kind = kind;
      await user.save();
  
      res.status(200).send('Kind updated successfully');
    } catch (error) {
        console.error('Server error:', error);
        res.status(500).send('Server error');
    }
  });
  

  const isProfileComplete = (user) => {
    const requiredFields = ['username', 'email', 'FullName', 'title', 'description', 'country', 'skills'];
  
    return requiredFields.every(field => {
      const fieldValue = user[field];
      return fieldValue && (typeof fieldValue === 'string' ? fieldValue.trim() !== '' : true);
    });
  };
  

  
  app.post('/user/:userId/claim-bonus/:bonusId', authenticate, async (req, res) => {
    const { userId, bonusId } = req.params;
    const user = await User.findById(userId).populate('tasks'); // Assicurati che 'tasks' sia il nome corretto
  
    if (!mongoose.Types.ObjectId.isValid(userId) || !mongoose.Types.ObjectId.isValid(bonusId)) {
      return res.status(400).send('Invalid ID');
    }
  
    if (user.bonuses.includes(bonusId)) {
      return res.status(400).send('Bonus already claimed');
    }
  
    const bonus = await Bonus.findById(bonusId);
    if (!bonus) {
      return res.status(404).send('Bonus not found');
    }
  
    // Aggiungi qui la logica per i bonus specifici
    if (bonus.title === 'Complete your profile!' && !isProfileComplete(user)) {
      return res.status(400).send('Profile is not complete');
    }
  
    if (bonus.title === 'Create your first Task!' && user.tasks.length === 0) {
      return res.status(400).send('No tasks created');
    }
  
    // Aggiungi il bonus all'utente
    user.points += bonus.points;
    user.bonuses.push(bonusId);
    await user.save();
  
    res.status(200).send('Bonus claimed successfully');
  });
  

const PORT = 4000;
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
