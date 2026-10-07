
(function () {
    "use strict";

    const launcher = document.getElementById("forensicsLauncher");
    const overlay = document.getElementById("forensicsOverlay");
    const close = document.getElementById("forensicsClose");
    const drop = document.getElementById("forensicsDrop");
    const input = document.getElementById("forensicsFile");
    const nameEl = document.getElementById("forensicsFileName");
    const status = document.getElementById("forensicsStatus");
    const result = document.getElementById("forensicsResult");
    const language = document.getElementById("forensicsLanguage");

    if (!launcher || !overlay) return;

    function openPanel() {
        overlay.classList.add("open");
        document.body.style.overflow = "hidden";
    }
    function closePanel() {
        overlay.classList.remove("open");
        document.body.style.overflow = "";
    }

    launcher.addEventListener("click", openPanel);
    close.addEventListener("click", closePanel);
    overlay.addEventListener("click", e => {
        if (e.target === overlay) closePanel();
    });
    document.addEventListener("keydown", e => {
        if (e.key === "Escape" && overlay.classList.contains("open")) closePanel();
    });

    function esc(value) {
        return String(value ?? "N/A")
            .replace(/&/g,"&amp;")
            .replace(/</g,"&lt;")
            .replace(/>/g,"&gt;")
            .replace(/"/g,"&quot;")
            .replace(/'/g,"&#039;");
    }

    function row(label, value) {
        return `<div class="forensics-row"><span>${esc(label)}</span><span>${esc(value)}</span></div>`;
    }

    function renderResult(data) {
        const common = [
            row("File", data.file_name),
            row("Type", data.file_type),
            row("MIME", data.mime_type),
            row("Size", data.file_size_human),
            row("SHA-256", data.sha256)
        ];

        let details = "";
        if (data.file_type === "IMAGE") {
            details = `
                ${row("Format", data.format)}
                ${row("Dimensions", `${data.width} × ${data.height}`)}
                ${row("Aspect ratio", data.aspect_ratio)}
                ${row("Color mode", data.mode)}
                ${row("EXIF present", data.has_exif ? "YES" : "NO")}
                ${row("GPS", data.gps_decimal ? `${data.gps_decimal.latitude}, ${data.gps_decimal.longitude}` : "Not available")}
            `;
        } else {
            details = `
                ${row("Pages", data.page_count)}
                ${row("PDF version", data.pdf_version)}
                ${row("Encrypted", data.encrypted ? "YES" : "NO")}
                ${row("Creator", data.creator)}
                ${row("Producer", data.producer)}
                ${row("Author", data.author)}
                ${row("Embedded images", data.embedded_image_count)}
                ${row("Fonts detected", data.font_count)}
            `;
        }

        const metadata = data.file_type === "IMAGE"
            ? Object.entries(data.exif || {}).map(([k,v]) => row(k,v)).join("") || row("EXIF", "No EXIF metadata available")
            : Object.entries(data.metadata || {}).map(([k,v]) => row(k,v)).join("") || row("PDF metadata", "No document metadata available");

        const notes = (data.notes || []).map(n => `<li>${esc(n)}</li>`).join("");

        result.innerHTML = `
            <div class="forensics-card">
                <h3>FILE IDENTIFICATION</h3>
                <div class="forensics-grid">${common.join("")}</div>
            </div>
            <div class="forensics-card">
                <h3>FORENSIC DETAILS</h3>
                <div class="forensics-grid">${details}</div>
            </div>
            <div class="forensics-card full">
                <h3>FORENSIC ASSESSMENT</h3>
                <div class="forensics-assessment">
                    <strong>${esc(data.forensic_assessment?.label || "INCONCLUSIVE")}</strong>
                    <p>${esc(data.forensic_assessment?.reason || "")}</p>
                </div>
            </div>
            <div class="forensics-card full">
                <h3>${data.file_type === "IMAGE" ? "EXIF METADATA" : "PDF METADATA"}</h3>
                <div class="forensics-grid">${metadata}</div>
            </div>
            <div class="forensics-card full">
                <h3>FORENSIC NOTES</h3>
                <ul class="forensics-list">${notes}</ul>
            </div>
        `;
    }

    async function analyzeFile(file) {
        if (!file) return;
        nameEl.textContent = file.name;
        status.textContent = "EXTRACTING FORENSIC DATA...";
        result.innerHTML = "";

        const form = new FormData();
        form.append("file", file);

        try {
            const response = await fetch("/api/forensics", {
                method: "POST",
                body: form
            });
            const data = await response.json();

            if (!response.ok || !data.success) {
                throw new Error(data.error || "Forensic analysis failed.");
            }

            renderResult(data.result);
            status.textContent = "FORENSIC ANALYSIS COMPLETE";
        } catch (error) {
            status.textContent = "ANALYSIS FAILED";
            result.innerHTML = `<div class="forensics-card full"><h3>ERROR</h3><p class="forensics-subtitle">${esc(error.message)}</p></div>`;
        }
    }

    input.addEventListener("change", () => analyzeFile(input.files[0]));
    ["dragenter","dragover"].forEach(type => {
        drop.addEventListener(type, e => {
            e.preventDefault();
            drop.classList.add("dragging");
        });
    });
    ["dragleave","drop"].forEach(type => {
        drop.addEventListener(type, e => {
            e.preventDefault();
            drop.classList.remove("dragging");
        });
    });
    drop.addEventListener("drop", e => analyzeFile(e.dataTransfer.files[0]));

    // Browser-native voice output; no external AI API required.
    window.sherlockSpeak = function (text) {
        if (!("speechSynthesis" in window)) return;
        window.speechSynthesis.cancel();
        const utterance = new SpeechSynthesisUtterance(text);
        utterance.lang = language ? language.value : "en-IN";
        utterance.rate = .94;
        window.speechSynthesis.speak(utterance);
    };

    if (language) {
        language.addEventListener("change", () => {
            document.documentElement.lang = language.value.startsWith("ta") ? "ta" :
                language.value.startsWith("hi") ? "hi" : "en";
        });
    }
})();
