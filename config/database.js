const { MONGO_URI } = process.env;
const mongoose = require("mongoose");

exports.connect = () => {
  //   console.log(MONGO_URI);
  mongoose
    .connect(MONGO_URI, {
      //   useNewUrlParser: true,
      //   useUnifiedTopology: true,
      //   useCreateIndex: true,
      //   useFindAndModify: false,
    })
    .then(() => {
      console.log("Successfully connected to the database");
    })
    .catch((error) => {
      console.log("Database connection failed. Exiting now...");
      console.error(error);
      process.exit(1);
    });
};
