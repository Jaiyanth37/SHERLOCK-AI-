/* ============================================================
   SHERLOCK CYBER INTELLIGENCE SYSTEM
   FRONTEND ENGINE
============================================================ */


/* ============================================================
   SHERLOCK INTRO LOADER
============================================================ */

function hideSherlockLoader() {

    const loader =
        document.getElementById("introLoader");

    if (!loader) {
        document.body.style.overflow = "auto";
        return;
    }

    loader.style.opacity = "0";
    loader.style.visibility = "hidden";
    loader.style.pointerEvents = "none";

    setTimeout(function () {

        loader.remove();

        document.body.style.overflow = "auto";

    }, 800);
}


/*
    Start loader removal after page is completely loaded.
*/

window.addEventListener("load", function () {

    setTimeout(function () {

        hideSherlockLoader();

    }, 3000);

});


/*
    FAILSAFE:
    If anything prevents the normal load event,
    Sherlock will still leave the intro screen.
*/

setTimeout(function () {

    hideSherlockLoader();

}, 5000);


/* Prevent scrolling during intro */

document.body.style.overflow = "hidden";


/* ============================================================
   SMOOTH SCROLL
============================================================ */

function scrollToAnalyzer() {

    const analyzer =
        document.getElementById("analyzer");

    if (!analyzer) {
        return;
    }

    analyzer.scrollIntoView({

        behavior: "smooth",

        block: "start"

    });

}


/* ============================================================
   DOM ELEMENTS
============================================================ */

let analyzeButton;
let threatInput;
let resultContainer;
let resultContent;
let resultStatus;


/* ============================================================
   INITIALIZE SHERLOCK
============================================================ */

function initializeSherlock() {

    analyzeButton =
        document.getElementById("analyzeButton");

    threatInput =
        document.getElementById("threatInput");

    resultContainer =
        document.getElementById("resultContainer");

    resultContent =
        document.getElementById("resultContent");

    resultStatus =
        document.getElementById("resultStatus");


    /* --------------------------------------------------------
       ANALYZE BUTTON
    -------------------------------------------------------- */

    if (analyzeButton) {

        analyzeButton.addEventListener(
            "click",
            analyzeThreat
        );

    }


    /* --------------------------------------------------------
       ENTER KEY
    -------------------------------------------------------- */

    if (threatInput) {

        threatInput.addEventListener(
            "keydown",
            function (event) {

                if (event.key === "Enter") {

                    event.preventDefault();

                    analyzeThreat();

                }

            }
        );

    }

}


/* ============================================================
   ANALYZE THREAT
============================================================ */

async function analyzeThreat() {

    if (!threatInput) {
        return;
    }


    const threat =
        threatInput.value.trim();


    /* --------------------------------------------------------
       EMPTY INPUT
    -------------------------------------------------------- */

    if (!threat) {

        threatInput.focus();

        const wrapper =
            threatInput.parentElement;

        if (wrapper) {

            wrapper.style.borderColor =
                "#ff4f6d";

            wrapper.style.boxShadow =
                "0 0 25px rgba(255,79,109,.25)";

        }

        setTimeout(function () {

            if (wrapper) {

                wrapper.style.borderColor = "";
                wrapper.style.boxShadow = "";

            }

        }, 1200);

        return;

    }


    /* ========================================================
       SHOW RESULT
    ======================================================== */

    if (resultContainer) {

        resultContainer.classList.remove("hidden");

    }


    if (resultStatus) {

        resultStatus.textContent =
            "ANALYZING";

    }


    if (resultContent) {

        resultContent.innerHTML = `

            <div class="analysis-loading">

                <div class="mini-loader">

                    <div class="mini-ring mini-ring-a"></div>

                    <div class="mini-ring mini-ring-b"></div>

                    <div class="mini-core"></div>

                </div>

                <div class="analysis-loading-text">

                    <div>
                        SHERLOCK INTELLIGENCE ENGINE
                    </div>

                    <span>
                        ANALYZING THREAT INDICATOR
                    </span>

                    <strong>
                        ${escapeHTML(threat)}
                    </strong>

                </div>

            </div>

        `;

    }


    if (resultContainer) {

        resultContainer.scrollIntoView({

            behavior: "smooth",

            block: "center"

        });

    }


    /* ========================================================
       SEND REQUEST TO FLASK
    ======================================================== */

    try {

        const response =
            await fetch(
                "/analyze",
                {

                    method: "POST",

                    headers: {

                        "Content-Type":
                            "application/json"

                    },

                    body: JSON.stringify({

                        threat: threat,

                        input: threat,

                        situation: threat

                    })

                }
            );


        if (!response.ok) {

            throw new Error(
                "Sherlock backend returned HTTP " +
                response.status
            );

        }


        const data =
            await response.json();


        /* ----------------------------------------------------
           ANALYSIS COMPLETE
        ---------------------------------------------------- */

        if (resultStatus) {

            resultStatus.textContent =
                "ANALYSIS COMPLETE";

        }


        if (resultContent) {

            resultContent.innerHTML =
                formatResult(data);

        }

    }


    catch (error) {

        console.error(
            "SHERLOCK ANALYSIS ERROR:",
            error
        );


        if (resultStatus) {

            resultStatus.textContent =
                "ENGINE ERROR";

        }


        if (resultContent) {

            resultContent.innerHTML = `

                <div class="analysis-fallback">

                    <div class="fallback-title">
                        SHERLOCK ENGINE ERROR
                    </div>

                    <strong>
                        ${escapeHTML(threat)}
                    </strong>

                    <p>
                        Sherlock could not complete the
                        analysis request. Check the Flask
                        server and try again.
                    </p>

                </div>

            `;

        }

    }

}


/* ============================================================
   FORMAT BACKEND RESULT
============================================================ */

function formatResult(data) {

    if (!data) {

        return `
            <div class="analysis-fallback">
                No analysis data returned.
            </div>
        `;

    }


    /*
        Flask normally returns:

        {
            success: true,
            result: {...}
        }

        Display the actual result instead of the
        complete API wrapper.
    */

    if (
        data.result &&
        typeof data.result === "object"
    ) {

        return formatSherlockResult(
            data.result
        );

    }


    if (typeof data === "string") {

        return `

            <pre class="result-json">
                ${escapeHTML(data)}
            </pre>

        `;

    }


    return `

        <pre class="result-json">
${escapeHTML(
    JSON.stringify(data, null, 2)
)}
        </pre>

    `;

}


/* ============================================================
   BEAUTIFUL SHERLOCK RESULT
============================================================ */

function formatSherlockResult(result) {

    const threat =
        result.threat || "Unknown";

    const level =
        result.level || "UNKNOWN";

    const confidence =
        result.confidence ?? 0;

    const reason =
        result.reason ||
        "No reasoning information available.";

    const action =
        result.action ||
        "No recommended action available.";

    const category =
        result.category ||
        "Unknown";

    const indicators =
        result.matched_indicators || [];

    const behaviors =
        result.behavior_indicators || [];

    const urls =
        result.url_indicators || [];

    const related =
        result.related_threats || [];

    const questionType =
        result.question_type ||
        "Threat Analysis";


    let mitreHTML = "";

    if (
        result.mitre &&
        !Array.isArray(result.mitre) &&
        result.mitre.id
    ) {

        mitreHTML = `

            <div class="result-detail">

                <span class="detail-label">
                    MITRE ATT&CK
                </span>

                <strong>
                    ${escapeHTML(result.mitre.id)}
                </strong>

                <small>
                    ${escapeHTML(
                        result.mitre.name || ""
                    )}
                </small>

            </div>

        `;

    }


    let indicatorHTML =
        indicators.length
        ? indicators.map(
            item =>
                `<span class="result-tag">
                    ${escapeHTML(item)}
                </span>`
        ).join("")
        : `<span class="result-muted">
                None
           </span>`;


    let behaviorHTML =
        behaviors.length
        ? behaviors.map(
            item =>
                `<span class="result-tag">
                    ${escapeHTML(item)}
                </span>`
        ).join("")
        : `<span class="result-muted">
                None
           </span>`;


    let relatedHTML =
        related.length
        ? related.map(
            item =>
                `<span class="result-tag">
                    ${escapeHTML(item)}
                </span>`
        ).join("")
        : `<span class="result-muted">
                None
           </span>`;


    return `

        <div class="sherlock-result">

            <!-- THREAT HEADER -->

            <div class="result-threat-header">

                <div>

                    <div class="result-label">
                        THREAT ASSESSMENT
                    </div>

                    <h3>
                        ${escapeHTML(threat)}
                    </h3>

                    <span class="result-category">
                        ${escapeHTML(category)}
                    </span>

                </div>


                <div class="risk-badge">

                    <span>
                        RISK
                    </span>

                    <strong>
                        ${escapeHTML(level)}
                    </strong>

                </div>

            </div>


            <!-- CONFIDENCE -->

            <div class="confidence-section">

                <div class="confidence-top">

                    <span>
                        SHERLOCK CONFIDENCE
                    </span>

                    <strong>
                        ${confidence}%
                    </strong>

                </div>

                <div class="confidence-bar">

                    <div
                        class="confidence-fill"
                        style="width:${Math.min(
                            100,
                            Math.max(
                                0,
                                Number(confidence)
                            )
                        )}%"
                    ></div>

                </div>

            </div>


            <!-- REASONING -->

            <div class="result-block">

                <div class="result-block-title">
                    WHY SHERLOCK FLAGGED THIS
                </div>

                <p>
                    ${escapeHTML(reason)}
                </p>

            </div>


            <!-- RECOMMENDED ACTION -->

            <div class="result-block action-block">

                <div class="result-block-title">
                    RECOMMENDED ACTION
                </div>

                <p>
                    ${escapeHTML(action)}
                </p>

            </div>


            <!-- DETAILS -->

            <div class="result-grid">

                <div class="result-detail">

                    <span class="detail-label">
                        QUESTION TYPE
                    </span>

                    <strong>
                        ${escapeHTML(questionType)}
                    </strong>

                </div>


                <div class="result-detail">

                    <span class="detail-label">
                        IOC TYPE
                    </span>

                    <strong>
                        ${escapeHTML(
                            result.ioc?.type ||
                            "UNKNOWN"
                        )}
                    </strong>

                </div>


                ${mitreHTML}

            </div>


            <!-- MATCHED INDICATORS -->

            <div class="result-block">

                <div class="result-block-title">
                    MATCHED INDICATORS
                </div>

                <div class="result-tags">

                    ${indicatorHTML}

                </div>

            </div>


            <!-- BEHAVIOURAL INDICATORS -->

            <div class="result-block">

                <div class="result-block-title">
                    BEHAVIOURAL SIGNALS
                </div>

                <div class="result-tags">

                    ${behaviorHTML}

                </div>

            </div>


            <!-- URL SIGNALS -->

            ${
                urls.length
                ? `

                    <div class="result-block">

                        <div class="result-block-title">
                            URL SIGNALS
                        </div>

                        <div class="result-tags">

                            ${urls.map(
                                item =>
                                    `<span class="result-tag">
                                        ${escapeHTML(item)}
                                    </span>`
                            ).join("")}

                        </div>

                    </div>

                `
                : ""
            }


            <!-- RELATED THREATS -->

            ${
                related.length
                ? `

                    <div class="result-block">

                        <div class="result-block-title">
                            RELATED THREATS
                        </div>

                        <div class="result-tags">

                            ${relatedHTML}

                        </div>

                    </div>

                `
                : ""
            }

        </div>

    `;

}


/* ============================================================
   HTML ESCAPE
============================================================ */

function escapeHTML(value) {

    return String(value)

        .replaceAll(
            "&",
            "&amp;"
        )

        .replaceAll(
            "<",
            "&lt;"
        )

        .replaceAll(
            ">",
            "&gt;"
        )

        .replaceAll(
            '"',
            "&quot;"
        )

        .replaceAll(
            "'",
            "&#039;"
        );

}


/* ============================================================
   MOUSE PARALLAX
============================================================ */

document.addEventListener(
    "mousemove",
    function (event) {

        const x =
            event.clientX /
            window.innerWidth -
            0.5;

        const y =
            event.clientY /
            window.innerHeight -
            0.5;


        const heroLogo =
            document.querySelector(
                ".hero-logo"
            );


        if (heroLogo) {

            heroLogo.style.marginLeft =
                `${x * 8}px`;

            heroLogo.style.marginTop =
                `${y * 8}px`;

        }


        const wordmark =
            document.querySelector(
                ".hero-wordmark"
            );


        if (wordmark) {

            wordmark.style.transform =
                `translate(
                    ${x * 4}px,
                    ${y * 4}px
                )`;

        }

    }
);


/* ============================================================
   CURSOR GLOW
============================================================ */

const cursorGlow =
    document.createElement("div");


cursorGlow.style.position =
    "fixed";

cursorGlow.style.width =
    "180px";

cursorGlow.style.height =
    "180px";

cursorGlow.style.borderRadius =
    "50%";

cursorGlow.style.pointerEvents =
    "none";

cursorGlow.style.zIndex =
    "-1";

cursorGlow.style.background =
    "radial-gradient(circle, rgba(50,210,255,.07), transparent 70%)";

cursorGlow.style.transform =
    "translate(-50%, -50%)";

document.body.appendChild(
    cursorGlow
);


document.addEventListener(
    "mousemove",
    function (event) {

        cursorGlow.style.left =
            event.clientX + "px";

        cursorGlow.style.top =
            event.clientY + "px";

    }
);


/* ============================================================
   ANALYZER CARD TILT
============================================================ */

document.addEventListener(
    "DOMContentLoaded",
    function () {

        initializeSherlock();


        const analysisInterface =
            document.querySelector(
                ".analysis-interface"
            );


        if (analysisInterface) {

            analysisInterface.addEventListener(
                "mousemove",
                function (event) {

                    const rect =
                        analysisInterface
                            .getBoundingClientRect();


                    const x =
                        event.clientX -
                        rect.left;


                    const y =
                        event.clientY -
                        rect.top;


                    const rotateX =
                        ((y / rect.height) - .5) *
                        -2;


                    const rotateY =
                        ((x / rect.width) - .5) *
                        2;


                    analysisInterface.style.transform =
                        `
                        perspective(1200px)
                        rotateX(${rotateX}deg)
                        rotateY(${rotateY}deg)
                        `;

                }
            );


            analysisInterface.addEventListener(
                "mouseleave",
                function () {

                    analysisInterface.style.transform =
                        "perspective(1200px) rotateX(0) rotateY(0)";

                }
            );

        }

    }
);


/* ============================================================
   DYNAMIC ANALYSIS LOADER
============================================================ */

const dynamicStyle =
    document.createElement("style");


dynamicStyle.textContent = `

.analysis-loading {
    display:flex;
    align-items:center;
    gap:25px;
    padding:30px;
    border-radius:18px;
    background:rgba(5,25,40,.35);
    border:1px solid rgba(70,220,255,.10);
}

.mini-loader {
    position:relative;
    width:70px;
    height:70px;
    flex-shrink:0;
    display:flex;
    justify-content:center;
    align-items:center;
}

.mini-ring {
    position:absolute;
    border-radius:50%;
}

.mini-ring-a {
    width:65px;
    height:65px;
    border:1px solid rgba(70,225,255,.35);
    border-top-color:#56eaff;
    animation:miniSpin 1.5s linear infinite;
}

.mini-ring-b {
    width:45px;
    height:45px;
    border:1px dashed rgba(70,200,255,.35);
    animation:miniSpinReverse 2s linear infinite;
}

.mini-core {
    width:12px;
    height:12px;
    border-radius:50%;
    background:#57eaff;
    box-shadow:
        0 0 15px #57eaff,
        0 0 30px rgba(40,210,255,.7);
    animation:miniPulse 1s infinite;
}

@keyframes miniSpin {
    from { transform:rotate(0deg); }
    to { transform:rotate(360deg); }
}

@keyframes miniSpinReverse {
    from { transform:rotate(360deg); }
    to { transform:rotate(0deg); }
}

@keyframes miniPulse {
    50% {
        transform:scale(1.5);
        opacity:.5;
    }
}

.analysis-loading-text {
    font-size:10px;
    letter-spacing:3px;
    color:#55ddff;
    line-height:2;
}

.analysis-loading-text span {
    display:block;
    color:rgba(190,220,230,.45);
    font-size:8px;
    letter-spacing:2px;
}

.analysis-loading-text strong {
    display:block;
    margin-top:5px;
    color:white;
    font-size:13px;
    letter-spacing:1px;
}

.analysis-fallback {
    padding:20px;
    color:rgba(200,230,240,.7);
}

.fallback-title {
    color:#55ddff;
    font-size:9px;
    letter-spacing:3px;
    margin-bottom:12px;
}

.analysis-fallback strong {
    color:white;
    font-size:15px;
}

.analysis-fallback p {
    margin-top:12px;
    color:rgba(190,220,230,.45);
}

.result-json {
    white-space:pre-wrap;
    font-family:monospace;
    font-size:12px;
    line-height:1.8;
    color:rgba(210,240,247,.75);
}

.sherlock-result {
    padding:5px;
}

.result-threat-header {
    display:flex;
    justify-content:space-between;
    align-items:flex-start;
    gap:20px;
    margin-bottom:30px;
}

.result-label {
    font-size:9px;
    letter-spacing:3px;
    color:#55ddff;
    margin-bottom:8px;
}

.result-threat-header h3 {
    margin:0;
    color:white;
    font-size:24px;
}

.result-category {
    display:block;
    margin-top:8px;
    color:rgba(190,220,230,.55);
    font-size:10px;
    letter-spacing:2px;
}

.risk-badge {
    min-width:110px;
    padding:14px;
    border:1px solid rgba(80,220,255,.2);
    border-radius:14px;
    text-align:center;
    background:rgba(20,50,70,.25);
}

.risk-badge span {
    display:block;
    font-size:8px;
    letter-spacing:2px;
    color:rgba(190,220,230,.45);
}

.risk-badge strong {
    display:block;
    margin-top:6px;
    color:#55ddff;
    font-size:14px;
}

.confidence-section {
    margin-bottom:28px;
}

.confidence-top {
    display:flex;
    justify-content:space-between;
    margin-bottom:8px;
    color:rgba(200,230,240,.55);
    font-size:9px;
    letter-spacing:2px;
}

.confidence-top strong {
    color:#55ddff;
}

.confidence-bar {
    width:100%;
    height:5px;
    background:rgba(255,255,255,.07);
    border-radius:99px;
    overflow:hidden;
}

.confidence-fill {
    height:100%;
    background:#55ddff;
    box-shadow:0 0 15px rgba(85,221,255,.7);
    transition:width .8s ease;
}

.result-block {
    margin-top:22px;
    padding:18px;
    border-radius:15px;
    background:rgba(5,20,35,.35);
    border:1px solid rgba(80,210,255,.08);
}

.result-block-title {
    font-size:8px;
    letter-spacing:2px;
    color:#55ddff;
    margin-bottom:10px;
}

.result-block p {
    color:rgba(220,240,245,.7);
    font-size:13px;
    line-height:1.7;
}

.result-grid {
    display:grid;
    grid-template-columns:repeat(3,1fr);
    gap:12px;
    margin-top:20px;
}

.result-detail {
    padding:15px;
    border-radius:14px;
    background:rgba(5,20,35,.35);
    border:1px solid rgba(80,210,255,.08);
}

.detail-label {
    display:block;
    font-size:8px;
    letter-spacing:2px;
    color:rgba(190,220,230,.4);
    margin-bottom:7px;
}

.result-detail strong {
    color:white;
    font-size:12px;
}

.result-detail small {
    display:block;
    margin-top:5px;
    color:rgba(190,220,230,.45);
    line-height:1.4;
}

.result-tags {
    display:flex;
    flex-wrap:wrap;
    gap:7px;
}

.result-tag {
    padding:7px 10px;
    border-radius:999px;
    background:rgba(60,210,255,.08);
    border:1px solid rgba(60,210,255,.14);
    color:rgba(210,240,247,.75);
    font-size:9px;
}

.result-muted {
    color:rgba(190,220,230,.35);
    font-size:10px;
}

@media(max-width:700px) {

    .result-threat-header {
        flex-direction:column;
    }

    .result-grid {
        grid-template-columns:1fr;
    }

    .analysis-loading {
        flex-direction:column;
        text-align:center;
    }

}

`;

document.head.appendChild(
    dynamicStyle
);


/* ============================================================
   END
============================================================ */