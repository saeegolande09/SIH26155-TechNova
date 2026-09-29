const { runSecurityAudit } = require("./services/auditService");

const filePath =
    "C:\\Users\\dhana\\OneDrive\\Desktop\\SIH26155\\backend\\uploads\\1790440695536-cisco-test.txt";

runSecurityAudit(filePath, "Cisco")
    .then((result) => {
        console.log("AUDIT RESULT:");
        console.log(JSON.stringify(result, null, 2));
    })
    .catch((error) => {
        console.error("AUDIT ERROR:", error.message);
    });