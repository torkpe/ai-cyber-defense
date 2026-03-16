// mlModel.js
const tf = require('@tensorflow/tfjs'); 
const fs = require('fs');
const path = require('path');



let model;

/**
 * Create a sequential model
 */
async function createModel() {
  model = tf.sequential();

  model.add(tf.layers.dense({ units: 16, inputShape: [6], activation: 'relu' }));
  model.add(tf.layers.dense({ units: 8, activation: 'relu' }));
  model.add(tf.layers.dense({ units: 1, activation: 'sigmoid' }));

  model.compile({
    optimizer: 'adam',
    loss: 'binaryCrossentropy',
    metrics: ['accuracy']
  });

  console.log("Model created");
  return model;
}

/**
 * Load dataset from JSON file
 * Each item: { features: [f1, f2, f3, f4, f5, f6], label: 0|1 }
 */
async function loadData(filePath) {
  try {
    const fullPath = path.resolve(__dirname, filePath);
    const rawData = fs.readFileSync(fullPath, 'utf8');
    const jsonData = JSON.parse(rawData);

    if (!Array.isArray(jsonData) || jsonData.length === 0) {
      throw new Error("Dataset JSON must be a non-empty array");
    }

    // Map features and labels
    const xs = jsonData.map((d, index) => {
      if (!Array.isArray(d.features) || d.features.length !== 6) {
        throw new Error(`Item at index ${index} must have a 'features' array of 6 numbers`);
      }
      return d.features.map(v => Number(v));
    });

    const ys = jsonData.map(d => [Number(d.label)]);

    return { xs: tf.tensor2d(xs), ys: tf.tensor2d(ys) };
  } catch (err) {
    console.error("Error loading dataset:", err.message);
    throw err;
  }
}

/**
 * Train the model
 * Provide path to JSON dataset relative to this file
 */
async function trainModel(datasetPath = 'data.json') {
  if (!model) throw new Error("Model not created yet. Call createModel() first.");

  let xs, ys;
  try {
    ({ xs, ys } = await loadData(datasetPath));
  } catch (err) {
    console.error("Training aborted: could not load dataset.");
    return;
  }

  try {
    await model.fit(xs, ys, {
      epochs: 100,
      shuffle: true,
      validationSplit: 0.2,
      callbacks: {
        onEpochEnd: (epoch, logs) => {
          if (epoch % 10 === 0) {
            console.log(
              `Epoch ${epoch}: loss=${logs.loss.toFixed(4)}, val_loss=${logs.val_loss.toFixed(4)}`
            );
          }
        }
      }
    });

    // === MODEL EVALUATION ===
    const evalResult = model.evaluate(xs, ys);

    evalResult[1].data().then(acc => {
        console.log("Model Accuracy:", acc[0]);
    });

    console.log("Model trained successfully");
  } catch (err) {
    console.error("Error during training:", err.message);
  }
}

/**
 * Make a prediction
 * Input: array of 6 numbers
 * Returns: number between 0 and 1
 */
async function predict(inputData) {
  try {
    if (!Array.isArray(inputData)) throw new Error("Input must be an array");
    if (inputData.length !== 6) throw new Error("Input array must have 6 features");

    const numericInput = inputData.map((v, i) => {
      const n = Number(v);
      if (isNaN(n)) throw new Error(`Feature at index ${i} is not a number`);
      return n;
    });

    const inputTensor = tf.tensor2d([numericInput]);
    const prediction = model.predict(inputTensor);
    const result = await prediction.data();

    return result[0];
  } catch (err) {
    console.error("Prediction error:", err.message);
    return null;
  }
}

async function predictFutureThreat(trendData) {
    const recentHighRisk = trendData.slice(-5).map(d => d.highRisk);

    const avg = recentHighRisk.reduce((a,b)=>a+b,0) / recentHighRisk.length;

    if (avg > 3) return "High probability of coordinated attack";
    if (avg > 1) return "Moderate risk trend emerging";

    return "Threat level stable";
}



module.exports = { createModel, trainModel, predict, predictFutureThreat };

// const tf = require('@tensorflow/tfjs');

// let model;

// async function createModel() {
//   model = tf.sequential();

//   model.add(tf.layers.dense({ units: 16, inputShape: [6], activation: 'relu' }));
//   model.add(tf.layers.dense({ units: 8, activation: 'relu' }));
//   model.add(tf.layers.dense({ units: 1, activation: 'sigmoid' }));

//   model.compile({
//     optimizer: 'adam',
//     loss: 'binaryCrossentropy',
//     metrics: ['accuracy']
//   });

//   return model;
// }

// // TRAIN MODEL (dummy data for now)
// async function trainModel() {
//   const xs = tf.tensor2d([
//     [1,0,0,1,0,1],
//     [0,1,1,0,1,0],
//     [1,1,0,1,0,0],
//     [0,0,1,0,1,1]
//   ]);

//   const ys = tf.tensor2d([
//     [1],
//     [0],
//     [1],
//     [0]
//   ]);

//   await model.fit(xs, ys, {
//     epochs: 50,
//     shuffle: true
//   });

//   console.log("Model trained successfully");
// }

// // PREDICT
// async function predict(inputData) {
//   const inputTensor = tf.tensor2d([inputData]);
//   const prediction = model.predict(inputTensor);
//   const result = await prediction.data();
//   return result[0];
// }

// module.exports = { createModel, trainModel, predict };