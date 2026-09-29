const { runDriftDetection } = require("./services/driftService");

const oldFile =
    "C:\\Users\\dhana\\OneDrive\\Desktop\\SIH26155\\backend\\uploads\\old-config.txt";

const newFile =
    "C:\\Users\\dhana\\OneDrive\\Desktop\\SIH26155\\backend\\uploads\\new-config.txt";

runDriftDetection(oldFile, newFile)
    .then((result) => {

        console.log("DRIFT RESULT:");

        console.log(
            JSON.stringify(result, null, 2)
        );

    })
    .catch((error) => {

        console.error(
            "DRIFT ERROR:",
            error.message
        );

    });