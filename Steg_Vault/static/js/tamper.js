let originalHash = "";
    let imgElement = new Image();
    let canvas = document.getElementById("watermarkedCanvas");
    let ctx = canvas.getContext("2d");

    // Function to clear result when a new image is uploaded for tampering detection
    function clearResult() {
        document.getElementById("originalHash").innerText = "N/A";
        document.getElementById("currentHash").innerText = "N/A";
        document.getElementById("tamperingStatus").innerText = "Not Checked";
        document.getElementById("tamperingStatus").classList.add("text-danger");
        document.getElementById("tamperingStatus").classList.remove("text-success");
    }

    // Function to Analyze Tampering
    function analyzeTampering() {
        const file = document.getElementById("imageUpload").files[0];
        if (!file) {
            alert("Please upload an image.");
            return;
        }

        // Disable the button while processing
        document.getElementById("tamperingButton").disabled = true;
        document.getElementById("loadingSpinner").style.display = "inline-block";

        const reader = new FileReader();
        reader.onload = function (event) {
            const fileContent = event.target.result;
            const currentHash = CryptoJS.SHA256(fileContent).toString();
            document.getElementById("currentHash").innerText = currentHash;

            if (originalHash === "") {
                originalHash = currentHash;
                document.getElementById("originalHash").innerText = originalHash;
                document.getElementById("tamperingStatus").innerText = "No Tampering Detected";
                document.getElementById("tamperingStatus").classList.remove("text-danger");
                document.getElementById("tamperingStatus").classList.add("text-success");
            } else {
                if (currentHash !== originalHash) {
                    document.getElementById("tamperingStatus").innerText = "Tampering Detected!";
                    document.getElementById("tamperingStatus").classList.remove("text-success");
                    document.getElementById("tamperingStatus").classList.add("text-danger");
                    addLog("Tampering Detected on uploaded file.");
                } else {
                    document.getElementById("tamperingStatus").innerText = "No Tampering Detected";
                    document.getElementById("tamperingStatus").classList.remove("text-danger");
                    document.getElementById("tamperingStatus").classList.add("text-success");
                }
            }

            // Enable the button and hide the loading spinner after the process
            document.getElementById("tamperingButton").disabled = false;
            document.getElementById("loadingSpinner").style.display = "none";
        };
        reader.readAsText(file);
    }

    // Function to Load Image for Watermarking
    function loadImageForWatermark() {
        const file = document.getElementById("watermarkImageUpload").files[0];
        if (!file) {
            alert("Please upload an image.");
            return;
        }

        const reader = new FileReader();
        reader.onload = function (event) {
            imgElement.onload = function() {
                canvas.width = imgElement.width;
                canvas.height = imgElement.height;
                ctx.drawImage(imgElement, 0, 0);
                document.getElementById("watermarkTextCard").style.display = "block";
            }
            imgElement.src = event.target.result;
        };
        reader.readAsDataURL(file);
    }

    // Function to Apply Watermark
    function applyWatermark() {
        const text = document.getElementById("watermarkText").value;
        if (!text) {
            alert("Please enter watermark text.");
            return;
        }

        ctx.clearRect(0, 0, canvas.width, canvas.height); // Clear canvas
        ctx.drawImage(imgElement, 0, 0); // Draw the original image
        ctx.font = "40px Arial";
        ctx.fillStyle = "rgba(255, 255, 255, 0.7)";
        ctx.textAlign = "center";
        ctx.textBaseline = "middle";
        ctx.fillText(text, canvas.width / 2, canvas.height / 2);

        alert("Watermark added successfully!");
        addLog("Watermark added: " + text);
    }

    // Function to Download Watermarked Image
    function downloadWatermarkedImage() {
        const dataUrl = canvas.toDataURL("image/png");
        const link = document.createElement('a');
        link.href = dataUrl;
        link.download = "watermarked_image.png";
        link.click();
    }

    // Function to Add Log Entry
    function addLog(message) {
        const logList = document.getElementById("logList");
        const newItem = document.createElement("li");
        newItem.classList.add("list-group-item");
        newItem.innerText = message;
        logList.appendChild(newItem);
    }