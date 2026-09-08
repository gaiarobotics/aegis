(function () {
    "use strict";
    var form = document.getElementById("login-form");
    var input = document.getElementById("api-key");
    var btn = document.getElementById("submit-btn");
    var errorEl = document.getElementById("error-msg");

    form.addEventListener("submit", function (event) {
        event.preventDefault();
        var key = input.value.trim();
        if (!key) return;

        btn.classList.add("loading");
        btn.disabled = true;
        errorEl.textContent = "";
        input.classList.remove("error");

        fetch("/auth/login", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ api_key: key })
        }).then(function (response) {
            if (response.ok) {
                window.location.reload();
                return;
            }
            return response.json().then(function (data) {
                if (response.status === 429) {
                    throw new Error("Too many attempts. Wait a moment.");
                }
                throw new Error(data.detail || "Authentication failed");
            });
        }).catch(function (error) {
            errorEl.textContent = error.message;
            input.classList.add("error");
            btn.classList.remove("loading");
            btn.disabled = false;
            input.select();
        });
    });
})();
