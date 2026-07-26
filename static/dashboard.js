// ======================================================
// CURRENT TIME
// ======================================================

function updateTime() {

    const now = new Date();

    const formattedTime =
        now.toLocaleString();

    document.getElementById("currentTime").textContent =
        "Last updated: " + formattedTime;
}

updateTime();

setInterval(updateTime, 1000);


// ======================================================
// PROTOCOL CHART
// ======================================================

const protocolData =
    document.getElementById("protocolData");


const tcp =
    Number(protocolData.dataset.tcp);

const udp =
    Number(protocolData.dataset.udp);

const dns =
    Number(protocolData.dataset.dns);

const icmp =
    Number(protocolData.dataset.icmp);


const chartCanvas =
    document.getElementById("protocolChart");


new Chart(chartCanvas, {

    type: "doughnut",

    data: {

        labels: [
            "TCP",
            "UDP",
            "DNS",
            "ICMP"
        ],

        datasets: [{

            data: [
                tcp,
                udp,
                dns,
                icmp
            ],

            borderWidth: 2

        }]

    },

    options: {

        responsive: true,

        maintainAspectRatio: false,

        cutout: "68%",

        plugins: {

            legend: {

                position: "right",

                labels: {

                    color: "#cbd5e1",

                    padding: 20,

                    usePointStyle: true

                }

            }

        }

    }

});


// ======================================================
// AUTO REFRESH
// ======================================================

// Refresh dashboard every 10 seconds so newly captured
// packets from SQLite become visible.

setTimeout(function () {

    window.location.reload();

}, 10000);