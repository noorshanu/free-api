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


app.use(express.json());
app.use(cors({
    origin: '*', // Just for testing purpose
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
    wallet: { type: String, unique: true },
    FullName: { type: String, required: true },
    verified: { type: Boolean, default: false },
    verificationToken: { type: String },
    registrationDate: { type: Date, default: Date.now },
    isPrivate: { type: Boolean, default: false },
    bonuses: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Bonus' }],
    points: { type: Number, default: 0 },
    title: { type: String, default: 'Master UI UX Designer' },
    description: { type: String, default: 'Lorem ipsum...' },
    skills: [{ type: String }],
    country: { type: String },
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

const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: 'warneed@gmail.com',
        pass: '@.@',
    },
});

const limiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 500,
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
    body('email').trim().isEmail().normalizeEmail(),
    body('password').isLength({ min: 6 }),
    body('wallet').trim().escape(),
    body('FullName').trim().escape().matches(/^[A-Za-z\s]+$/),
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    const { username, email, password, wallet, FullName } = req.body;

    const existingEmail = await User.findOne({ email });
    if (existingEmail) {
        return res.status(400).send('Email already exists');
    }

    const existingUserName = await User.findOne({ username });
    if (existingUserName) {
        return res.status(400).send('Username already exists');
    }

    const existingWallet = await User.findOne({ wallet });
    if (existingWallet) {
        return res.status(400).send('Wallet Address already exists');
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const verificationToken = crypto.randomBytes(20).toString('hex');
    const newUser = new User({ username, email, password: hashedPassword, wallet, FullName, verificationToken });
    await newUser.save();

    const mailOptions = {
        from: 'info.robertocinque@gmail.com',
        to: email,
        subject: 'Verifica il tuo indirizzo email',
        text: `Clicca sul link per verificare il tuo indirizzo email:http://127.0.0.1:3000/email-verify?token=${verificationToken}`,
        html: `<p>Clicca sul link per verificare il tuo indirizzo email: <a href="http://127.0.0.1:3000/email-verify?token=${verificationToken}">Verifica email</a></p>`,
    };

    transporter.sendMail(mailOptions, (error, info) => {
        if (error) {
            return console.log(error);
        }
        console.log('Email sent: ' + info.response);
    });

    res.status(201).send('User registered successfully');
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

        const token = jwt.sign({ id: user._id }, 'secret_key', { expiresIn: '1h' });

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
        const bonuses = await Bonus.find();
        const availableBonuses = bonuses.filter(bonus => !user.bonuses.includes(bonus._id));
        res.json({ bonuses: availableBonuses });
    } catch (error) {
        console.log(error);
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
      const jobPost = await JobPost.findById(req.params.jobId).populate('userId');
      if (!jobPost) return res.status(404).send('Job not found');
      res.json(jobPost);
    } catch (err) {
      console.error(err);
      res.status(500).send('Server error');
    }
  });


app.post('/user/:userId/claim-bonus/:bonusId', authenticate, async (req, res) => {
    const { userId, bonusId } = req.params;

    if (!mongoose.Types.ObjectId.isValid(userId) || !mongoose.Types.ObjectId.isValid(bonusId)) {
        return res.status(400).send('Invalid ID');
    }

    try {
        const user = await User.findById(userId);
        if (!user) {
            return res.status(404).send('User not found');
        }

        if (user._id.toString() !== req.userId) {
            return res.status(401).send('Unauthorized');
        }

        const bonus = await Bonus.findById(bonusId);
        if (!bonus) {
            return res.status(404).send('Bonus not found');
        }

        if (user.bonuses.includes(bonusId)) {
            return res.status(400).send('Bonus already claimed');
        }

        user.points += bonus.points;
        user.bonuses.push(bonusId);
        await user.save();

        res.status(200).send('Bonus claimed successfully');
    } catch (error) {
        console.log('Server error:', error);
        res.status(500).send('Server error');
    }
});

const PORT = 4000;
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
