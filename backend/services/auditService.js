const { spawn } = require("child_process");
const path = require("path");

function runSecurityAudit(filePath, vendor) {

    return new Promise((resolve, reject) => {

        const pythonPath = "python";

        const scriptPath = path.join(
            __dirname,
            "../../security-engine/main.py"
        );

        const pythonProcess = spawn(
            pythonPath,
            [scriptPath, filePath, vendor]
        );

        let output = "";
        let errorOutput = "";

        pythonProcess.stdout.on("data", (data) => {
            output += data.toString();
        });

        pythonProcess.stderr.on("data", (data) => {
            errorOutput += data.toString();
        });

        pythonProcess.on("close", (code) => {

            if (code !== 0) {
                return reject(
                    new Error(errorOutput || "Python audit failed")
                );
            }

            try {

                const result = JSON.parse(output);

                resolve(result);

            } catch (error) {

                reject(
                    new Error("Invalid JSON returned by Python engine")
                );
            }
        });
    });
}

module.exports = {
    runSecurityAudit
};