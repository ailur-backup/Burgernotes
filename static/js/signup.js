if (localStorage.getItem("DONOTSHARE-secretkey") !== null) {
    window.location.replace("/app")
    document.body.innerHTML = "Redirecting.."
    throw new Error();
}
if (localStorage.getItem("DONOTSHARE-password") !== null) {
    window.location.replace("/app")
    document.body.innerHTML = "Redirecting.."
    throw new Error();
}

let usernameBox = document.getElementById("usernameBox")
let passwordBox = document.getElementById("passwordBox")
let statusBox = document.getElementById("statusBox")
let signupButton = document.getElementById("signupButton")

function showElements(yesorno) {
    if (!yesorno) {
        usernameBox.classList.add("hidden")
        passwordBox.classList.add("hidden")
        signupButton.classList.add("hidden")
    }
    else {
        usernameBox.classList.remove("hidden")
        passwordBox.classList.remove("hidden")
        signupButton.classList.remove("hidden")
    }
}

signupButton.addEventListener("click", (event) => {
    async function doStuff() {
        let username = usernameBox.value
        let password = passwordBox.value

        if (username == "") {
            statusBox.innerText = "username required"
            return
        }
        if ((username).length > 20) {
            statusBox.innerText = "username cannot be more than 20 characters"
            return
        }
        if (password == "") {
            statusBox.innerText = "password required"
            return
        }
        if ((password).length < 14) {
            statusBox.innerText = "14 characters required"
            return
        }

        showElements(false)
        statusBox.innerText = "creating account, please hold on.."

        async function hashpass(pass) {
            const key = await hashwasm.argon2id({
                password: pass,
                salt: await hashwasm.sha512(pass),
                parallelism: 1,
                iterations: 256,
                memorySize: 512,
                hashLength: 32,
                outputType: "encoded"
            });
            return key
        };

        fetch("/api/signup", {
            method: "POST",
            body: JSON.stringify({
                username: username,
                password: await hashpass(password)
            }),
            headers: {
                "Content-type": "application/json; charset=UTF-8"
            }
        })
            .then((response) => response)
            .then((response) => {
                async function doStuff() {
                    let responseData = await response.json()

                    if (response.status == 200) {
                        statusBox.innerText == "redirecting.."
                        localStorage.setItem("DONOTSHARE-secretkey", responseData["key"])
                        localStorage.setItem("DONOTSHARE-password", await hashwasm.sha512(password))

                        window.location.href = "/app"
                    }
                    else if (response.status == 409) {
                        statusBox.innerText = "username already taken!"
                        showElements(true)
                    }
                    else {
                        statusBox.innerText = "something went wrong! (error code: " + respStatus + ")"
                        showElements(true)
                    }
                }
                doStuff()
            });
    }
    doStuff()
});