const { spawn } = require("child_process");
const path = require("path");
const fs = require("fs");


function runNormalization(filePath, vendor) {

    return new Promise((resolve, reject) => {

        const pythonPath = "python";


        // ==========================================
        // SELECT VENDOR PARSER
        // ==========================================

        let parserFile;

        if (vendor === "Cisco") {

            parserFile = "cisco_parser.py";

        } else if (vendor === "Juniper") {

            parserFile = "juniper_parser.py";

        } else if (vendor === "Fortinet") {

            parserFile = "fortinet_parser.py";

        } else {

            return reject(
                new Error(
                    "Unsupported vendor: " + vendor
                )
            );

        }


        // ==========================================
        // PARSER PATH
        // ==========================================

        const parserPath = path.join(
            __dirname,
            "../../security-engine/parsers",
            parserFile
        );


        // ==========================================
        // NORMALIZER PATH
        // ==========================================

        const normalizerPath = path.join(
            __dirname,
            "../../security-engine/normalization/normalizer.py"
        );


        // ==========================================
        // TEMP JSON FILE
        // ==========================================

        const tempJsonPath = path.join(
            __dirname,
            "../uploads",
            `parser-output-${Date.now()}.json`
        );


        // ==========================================
        // RUN VENDOR PARSER
        // ==========================================

        const parserProcess = spawn(
            pythonPath,
            [
                parserPath,
                filePath
            ]
        );


        let parserOutput = "";
        let parserError = "";


        parserProcess.stdout.on(
            "data",
            (data) => {

                parserOutput += data.toString();

            }
        );


        parserProcess.stderr.on(
            "data",
            (data) => {

                parserError += data.toString();

            }
        );


        // ==========================================
        // PARSER COMPLETED
        // ==========================================

        parserProcess.on(
            "close",
            (code) => {

                if (code !== 0) {

                    return reject(
                        new Error(
                            parserError ||
                            "Vendor parser failed"
                        )
                    );

                }


                // ==================================
                // CHECK PARSER JSON
                // ==================================

                let parsedData;

                try {

                    parsedData =
                        JSON.parse(
                            parserOutput
                        );

                } catch (error) {

                    return reject(
                        new Error(
                            "Invalid JSON returned by vendor parser"
                        )
                    );

                }


                // ==================================
                // SAVE PARSER OUTPUT
                // ==================================

                try {

                    fs.writeFileSync(
                        tempJsonPath,
                        JSON.stringify(
                            parsedData,
                            null,
                            2
                        ),
                        "utf8"
                    );

                } catch (error) {

                    return reject(
                        new Error(
                            "Failed to create temporary parser output file"
                        )
                    );

                }


                // ==================================
                // RUN NORMALIZER
                // ==================================

                const normalizerProcess =
                    spawn(
                        pythonPath,
                        [
                            normalizerPath,
                            tempJsonPath
                        ]
                    );


                let normalizedOutput = "";
                let normalizerError = "";


                normalizerProcess.stdout.on(
                    "data",
                    (data) => {

                        normalizedOutput +=
                            data.toString();

                    }
                );


                normalizerProcess.stderr.on(
                    "data",
                    (data) => {

                        normalizerError +=
                            data.toString();

                    }
                );


                // ==================================
                // NORMALIZER COMPLETED
                // ==================================

                normalizerProcess.on(
                    "close",
                    (normalizerCode) => {


                        // ==========================
                        // DELETE TEMP FILE
                        // ==========================

                        try {

                            if (
                                fs.existsSync(
                                    tempJsonPath
                                )
                            ) {

                                fs.unlinkSync(
                                    tempJsonPath
                                );

                            }

                        } catch (error) {

                            console.log(
                                "Temporary file cleanup failed:",
                                error.message
                            );

                        }


                        // ==========================
                        // CHECK NORMALIZER
                        // ==========================

                        if (
                            normalizerCode !== 0
                        ) {

                            return reject(
                                new Error(
                                    normalizerError ||
                                    "Normalization failed"
                                )
                            );

                        }


                        // ==========================
                        // PARSE NORMALIZED JSON
                        // ==========================

                        try {

                            const result =
                                JSON.parse(
                                    normalizedOutput
                                );


                            resolve(
                                result
                            );


                        } catch (error) {

                            reject(
                                new Error(
                                    "Invalid JSON returned by normalizer"
                                )
                            );

                        }

                    }
                );

            }
        );

    });

}


module.exports = {
    runNormalization
};