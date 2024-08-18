document.addEventListener("DOMContentLoaded", () => {
    if (document.getElementById("items")) {
        fetchItems();
    }
    if (document.getElementById("login-form")) {
        document.getElementById("login-form").addEventListener("submit", loginUser);
    }
    if (document.getElementById("rent-button")) {
        document.getElementById("rent-button").addEventListener("click", rentItem);
    }
});

async function fetchItems() {
    const response = await fetch("/items/");
    const items = await response.json();
    const itemsList = document.getElementById("items");
    items.forEach(item => {
        const li = document.createElement("li");
        li.innerHTML = `<a href="/items/${item.id}">${item.name}</a>`;
        itemsList.appendChild(li);
    });
}

async function loginUser(event) {
    event.preventDefault();
    const form = event.target;
    const username = form.username.value;
    const password = form.password.value;

    const response = await fetch("/token", {
        method: "POST",
        headers: {
            "Content-Type": "application/x-www-form-urlencoded",
        },
        body: `username=${username}&password=${password}`,
    });

    if (response.ok) {
        const data = await response.json();
        localStorage.setItem("token", data.access_token);
        window.location.href = "/";
    } else {
        alert("Login failed!");
    }
}

async function rentItem() {
    const token = localStorage.getItem("token");
    if (!token) {
        alert("Please login first!");
        return;
    }

    const itemId = window.location.pathname.split("/").pop();
    const startDate = prompt("Enter start date (YYYY-MM-DD):");
    const endDate = prompt("Enter end date (YYYY-MM-DD):");

    const response = await fetch("/rentals/", {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
            "Authorization": `Bearer ${token}`,
        },
        body: JSON.stringify({ item_id: parseInt(itemId), start_date: startDate, end_date: endDate }),
    });

    if (response.ok) {
        alert("Item rented successfully!");
        window.location.href = "/";
    } else {
        alert("Failed to rent item!");
    }
}