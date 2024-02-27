if (localStorage.getItem("DONOTSHARE-secretkey") !== null) {
    window.location.replace("../app/index.html")
    document.body.innerHTML = "Redirecting..."
    throw new Error();
}
if (localStorage.getItem("DONOTSHARE-password") !== null) {
    window.location.replace("../app/index.html")
    document.body.innerHTML = "Redirecting..."
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
            statusBox.innerText = "A username is required!"
            return
        }
        if ((username).length > 20) {
            statusBox.innerText = "Username cannot be more than 20 characters!"
            return
        }
        if (password == "") {
            statusBox.innerText = "A password is required!"
            return
        }
        if ((password).length < 8) {
            statusBox.innerText = "8 or more characters are required!"
            return
        }

        showElements(false)
        statusBox.innerText = "Creating account, please hold on..."

        async function hashpass(pass) {
            let key = pass
            for (let i = 0; i < 128; i++) {
                key = await hashwasm.sha3(key)
            }
            return key
        };


        fetch("https://notes.hectabit.org/api/signup", {
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

                        window.location.href = "../app/index.html"
                    }
                    else if (response.status == 409) {
                        statusBox.innerText = "Username already taken!"
                        showElements(true)
                    }
                    else {
                        statusBox.innerText = "Something went wrong!"
                        showElements(true)
                    }
                }
                doStuff()
            });
    }
    doStuff()
});
