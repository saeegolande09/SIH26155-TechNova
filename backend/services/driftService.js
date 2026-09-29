const { spawn } = require("child_process");
const path = require("path");

function runDriftDetection(oldFilePath, newFilePath) {

    return new Promise((resolve, reject) => {

        const pythonPath = "python";

        const scriptPath = path.join(
            __dirname,
            "../../security-engine/drift/drift_detector.py"
        );

        const pythonProcess = spawn(
            pythonPath,
            [
                scriptPath,
                oldFilePath,
                newFilePath
            ]
        );

        let output = "";
        let errorOutput = "";

        pythonProcess.stdout.on("data", (data) => {
            output += data.toString();
        });

        pythonProcess.stderr.on("data", (data) => {
            errorOutput += data.toString();
        });

        pythonProcess.on("error", (error) => {
            reject(
                new Error(
                    "Failed to start Python process: " +
                    error.message
                )
            );
        });

        pythonProcess.on("close", (code) => {

            if (code !== 0) {

                return reject(
                    new Error(
                        errorOutput ||
                        "Drift detection failed"
                    )
                );
            }

            try {

                const result = JSON.parse(output);

                resolve(result);

            } catch (error) {

                console.error(
                    "Python output:",
                    output
                );

                reject(
                    new Error(
                        "Invalid JSON returned by drift engine"
                    )
                );
            }
        });
    });
}

module.exports = {
    runDriftDetection
};