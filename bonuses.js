const mongoose = require('mongoose');

mongoose.connect('mongodb://localhost:27017/platform', {
    useNewUrlParser: true,
    useUnifiedTopology: true,
});

const bonusSchema = new mongoose.Schema({
    title: { type: String, required: true },
    points: { type: Number, required: true },
});

const Bonus = mongoose.model('Bonus', bonusSchema);

const bonuses = [
    { title: 'Welcome Bonus!', points: 100 },
    { title: 'Create first Task!', points: 10 },
    // ... altri bonus
];

Bonus.insertMany(bonuses)
    .then(() => {
        console.log('Bonuses inserted successfully');
        mongoose.connection.close();
    })
    .catch((err) => {
        console.log('Error inserting bonuses:', err);
        mongoose.connection.close();
    });
