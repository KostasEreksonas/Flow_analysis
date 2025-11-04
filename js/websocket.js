const flow_counts = {}; // Data to graph how many flows were instantiated from which IP address

const ctx = document.getElementById('myChart').getContext('2d');
const config = {
	type: 'bar',
	data: {
		labels: [],  // Source IP addresses
		datasets: [{
			label: 'Flow Count',
			data: [],  // Counts per IP
			backgroundColor: 'rgba(75, 192, 192, 0.2)',
			borderColor: 'rgba(75, 192, 192, 1)'
		}]
	}
}

const myChart = new Chart(ctx, config);

function updateChart(src_ip, count){
	const index = myChart.data.labels.indexOf(src_ip);

	if (index === -1) {
		myChart.data.labels.push(src_ip);
    		myChart.data.datasets[0].data.push(count);
	} else {
		myChart.data.datasets[0].data[index] = count;
	}

	myChart.update();
}

var ws = new WebSocket("ws://localhost:8000/ws");

ws.onopen = function(event) {
        console.log('Connected to WebSocket');
};

ws.onmessage = function(event) {
	data = JSON.parse(event.data);	

	let date = new Date(data['termination'] * 1000);
	let hours = date.getHours();
	let minutes = "0" + date.getMinutes();
	let seconds = "0" + date.getSeconds();
	let formattedTime = hours + ':' + minutes.substr(-2) + ':' + seconds.substr(-2)

	let table = document.getElementById("flow");
	let row = table.insertRow();
	let flow_id = row.insertCell(0);
	let timestamp = row.insertCell(1);
	let source = row.insertCell(2);
	let destination = row.insertCell(3);
	let protocol = row.insertCell(4);
	let anomaly = row.insertCell(5);
	let termination = row.insertCell(6);
	let extended_stats = row.insertCell(7);

	flow_id.innerHTML = data['flow_id'];
	timestamp.innerHTML = formattedTime;
	source.innerHTML = `${data['original_flow_key'][0]}:${data['original_flow_key'][2]}`;
	destination.innerHTML = `${data['original_flow_key'][1]}:${data['original_flow_key'][3]}`;
	protocol.innerHTML = data['original_flow_key'][4];
	anomaly.innerHTML = data['anomalies'];
	termination.innerHTML = data['reason'];
	//console.log(data);

	let button = document.createElement('button');
	button.textContent = 'Details';
	button.className = 'btn btn-primary';

	button.dataset.results = JSON.stringify(data['results'] || {});;
	button.dataset.stats = JSON.stringify(data['stats'] || {});;
	button.dataset.flowId = data['flow_id'];

	// Add click event to open modal
	button.onclick = function() {
		openModal(this.dataset);
	};
	
	extended_stats.appendChild(button);

	src_ip = data['original_flow_key'][0];
	if (src_ip in flow_counts) {
		flow_counts[src_ip] += 1;
	} else {
		flow_counts[src_ip] = 1;
	}

	updateChart(src_ip, flow_counts[src_ip]);
};

ws.onclose = function(event) {
	console.log('WebSocket connection closed');
};

// Function to open and populate modal
function openModal(flowData) {
	const modal = document.getElementById('flowModal');
	const modalContent = document.getElementById('modalFlowDetails');

	// Parse the stored JSON data
	const results = JSON.parse(flowData.results);
	const stats = JSON.parse(flowData.stats);

	let content = `<h3>Flow ID: ${flowData['flowId']}</h3>`;

	content += "<h1>Attack Probabilites</h1>";
	content += "<table class=table>";
	content += "<thead>";
	content += "<tr><th>Attack</th>";
	content += "<th>Probability</th></th>";
	content += "</thead>";
	content += "<tbody>";
	for (const key in results){
		content += `<tr><td>${key}</td><td>${results[key]}</td></tr>`
	}
	content += "</tbody>";
	content += "</table>";

	content += "<h1>Statistical Features</h1>";
	content += "<table class=table>";
	content += "<thead>";
	content += "<tr><th>Feature Name</th>";
	content += "<th>Value</th></th>";
	content += "</thead>";
	content += "<tbody>";
	for (const key in stats){
		content += `<tr><td>${key}</td><td>${stats[key]}</td></tr>`
	}
	content += "</tbody>";
	content += "</table>";

	modalContent.innerHTML = content;
	modal.style.display = 'block';
}

// Close modal when clicking the X
function closeModal() {
    document.getElementById('flowModal').style.display = 'none';
}

// Bar chart
let data = {
	labels: [],
        datasets: [{
        	label: 'Sample Bar Chart',
                data: [],
                backgroundColor: 'rgba(70, 192, 192, 0.6)',
                borderColor: 'rgba(150, 100, 255, 1)',
                borderWidth: 1
        }]
};
