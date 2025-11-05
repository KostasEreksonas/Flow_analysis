const src_flow_counts = {}; // Flow counts instantiated by source IP
const dst_flow_counts = {}; // Flow counts instantiated by destination IP

const source_flow_graph = document.getElementById('src_chart').getContext('2d');
const destination_flow_graph = document.getElementById('dst_chart').getContext('2d');

const source_config = {
	type: 'bar',
	data: {
		labels: [],  // Source IP addresses
		datasets: [{
			label: 'Flow Count',
			data: [],  // Counts per IP
			backgroundColor: 'rgba(56, 48, 191, 0.8)',
			borderColor: 'rgba(27, 6, 11, 0.8)'
		}]
	}
}

const destination_config = {
	type: 'bar',
	data: {
		labels: [],  // Source IP addresses
		datasets: [{
			label: 'Flow Count',
			data: [],  // Counts per IP
			backgroundColor: 'rgba(56, 48, 191, 0.8)',
			borderColor: 'rgba(27, 6, 11, 0.8)'
		}]
	}
}

const src_chart = new Chart(source_flow_graph, source_config);
const dst_chart = new Chart(destination_flow_graph, destination_config);

function update_src_chart(src_ip, count){
	const index = src_chart.data.labels.indexOf(src_ip);

	if (index === -1) {
		src_chart.data.labels.push(src_ip);
    	src_chart.data.datasets[0].data.push(count);
	} else {
		src_chart.data.datasets[0].data[index] = count;
	}

	src_chart.update();
}

function update_dst_chart(dst_ip, count){
	const index = dst_chart.data.labels.indexOf(dst_ip);

	if (index === -1) {
		dst_chart.data.labels.push(dst_ip);
    	dst_chart.data.datasets[0].data.push(count);
	} else {
		dst_chart.data.datasets[0].data[index] = count;
	}

	dst_chart.update();
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
	let row = table.insertRow(0); // Latest flow records will be inserted at the top of the table
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
	if (src_ip in src_flow_counts) {
		src_flow_counts[src_ip] += 1;
	} else {
		src_flow_counts[src_ip] = 1;
	}
	update_src_chart(src_ip, src_flow_counts[src_ip]);

	dst_ip = data['original_flow_key'][1];
	if (dst_ip in dst_flow_counts) {
		dst_flow_counts[dst_ip] += 1;
	} else {
		dst_flow_counts[dst_ip] = 1;
	}
	update_dst_chart(dst_ip, dst_flow_counts[dst_ip]);
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

    content += "<div class=\"row\">";

    content += "<div class=\"col-md-6\">";
	content += "<h1 class=\"text-center\">Attack Probabilites</h1>";
	content += "<table class=\"table table-bordered table-striped table-hover\">";
	content += "<thead>";
	content += "<tr><th scope=\"col\">Attack</th><th scope=\"col\">Probability</th></th>";
	content += "</thead>";
	content += "<tbody>";
	for (const key in results){
		content += `<tr><td>${key}</td><td>${results[key]}</td></tr>`
	}
	content += "</tbody>";
	content += "</table>";
    content += "</div>";

    content += "<div class=\"col-md-6\">";
	content += "<h1 class=\"text-center\">Statistical Features</h1>";
	content += "<table class=\"table table-bordered table-striped table-hover\">";
	content += "<thead>";
	content += "<tr><th scope=\"col\">Feature Name</th><th scope=\"col\">Value</th></th>";
	content += "</thead>";
	content += "<tbody>";
	for (const key in stats){
		content += `<tr><td>${key}</td><td>${stats[key]}</td></tr>`
	}
	content += "</tbody>";
	content += "</table>";
	content += "</div>";

	content += "</div>";

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
