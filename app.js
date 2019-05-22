const express = require('express');
const app = express();
const port = 3000;

/*********** HELPER FUNCTIONS ***********/
/** adapted from https://stackoverflow.com/questions/6832596/how-to-compare-software-version-number-using-js-only-number */
function versionCompare(v1, v2, options) {
    let lexicographical = options && options.lexicographical,
        zeroExtend = !options || options.zeroExtend !== false,
        v1parts = v1.split('.'),
        v2parts = v2.split('.');

    let isValidPart = (x) => (lexicographical ? /^\d+[A-Za-z]*$/ : /^\d+$/).test(x);

    if (!v1parts.every(isValidPart) || !v2parts.every(isValidPart)) {
        return NaN;
    }

    if (zeroExtend) {
        while (v1parts.length < v2parts.length) v1parts.push("0");
        while (v2parts.length < v1parts.length) v2parts.push("0");
    }

    if (!lexicographical) {
        v1parts = v1parts.map(Number);
        v2parts = v2parts.map(Number);
    }

    for (let i = 0; i < v1parts.length; ++i) {
        if (v2parts.length == i) {
            return 1;
        }

        if (v1parts[i] == v2parts[i]) {
            continue;
        }
        else if (v1parts[i] > v2parts[i]) {
            return 1;
        }
        else {
            return -1;
        }
    }

    if (v1parts.length != v2parts.length) {
        return -1;
    }

    return 0;
}

/*********** API ***********/
const VULNERABLE_PACKAGES = {
    "org.apache.maven.plugins": {
        "maven-compiler-plugin": [
            {
                cve: 'CVE-2019-10078', //dummy value
                version_from: "3.0",
                version_to: "3.1.5"
            },
            {
                cve: 'CVE-2018-3233', //dummy value
                version_from: "1.15.0",
                version_to: "3.12.42", //should fail on 3.2
            }
        ],
        "maven-dependency-plugin": [
            {
                cve: 'CVE-2014-1051', //dummy value
                version_from: "2.7",
                version_to: "3.12"
            }
        ],
    },
    "org.apache.tomcat.maven": {
        "tomcat7-maven-plugin": [
            {
                cve: 'CVE-2016-21343', //dummy value
                version_from: "1.0.8",
                version_to: "3.1.29"
            }
        ],
    }
};

app.get('/', (req, res) => res.send('Hello World!'));

app.get('/query', (req, res) => {
    let groupId = req.query.groupId;
    let artifactId = req.query.artifactId;
    let version = req.query.version;
    if (!groupId || !artifactId || !version) {
        throw "missing_params";
    }
    if (VULNERABLE_PACKAGES[groupId] && VULNERABLE_PACKAGES[groupId][artifactId]) {
        let affectedVersions = VULNERABLE_PACKAGES[groupId][artifactId];
        affectedVersions.forEach((affectedObj) => {
            if ((versionCompare(version, affectedObj.version_from) >= 0) &&
                (versionCompare(version, affectedObj.version_to) <= 0)) {
                console.log(version);
                console.log(affectedObj.version_from);
                console.log(affectedObj.version_to);
                throw "found vulnerability: " + affectedObj.cve;
            }
        });
    }

    res.send("OK");
});

app.listen(port, () => console.log(`Example app listening on port ${port}!`));