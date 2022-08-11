import React from "react";
import {Button, Card, Col, Form, Row} from "react-bootstrap";
import Container from "react-bootstrap/Container";

export const Experiment = () => (
    <Container>
        <Row>
            <Col>
                <Card>
                    <Card.Header>Experiment runner</Card.Header>
                    <Card.Body>
                        <Card.Title>Please define the parameters of the workload.</Card.Title>
                        <ExperimentRunnerForm/>
                    </Card.Body>
                    <Card.Footer className="text-muted">
                        <ResetSimulatorButton/>
                        <div className="mt-3 d-grid gap-2">
                            <Button variant="outline-danger" size="lg" onClick={destroyEnclaveRequest}>
                                Destroy Enclave
                            </Button>
                        </div>
                        <div className="mt-3 d-grid gap-2">
                            <Button variant="outline-info" size="lg" onClick={() => clearRequest("index_locality_cache")}>
                                Clear Locality Cache
                            </Button>
                        </div>
                        <div className="mt-3 d-grid gap-2">
                            <Button variant="outline-primary" size="lg" onClick={() => clearRequest("packet_stash")}>
                                Clear Packet Stash
                            </Button>
                        </div>
                        <div className="mt-3 d-grid gap-2">
                            <Button variant="outline-success" size="lg" onClick={() => urlRequest("oram_benchmark")}>
                                ORAM Benchmark
                            </Button>
                        </div>
                    </Card.Footer>
                </Card>
            </Col>
        </Row>
    </Container>
)

function destroyEnclaveRequest() {
    let ajaxRequest = new XMLHttpRequest();
    let url = "http://127.0.0.1:5000/" + "destroy_enclave";
    ajaxRequest.open('GET', url, true);
    ajaxRequest.setRequestHeader("Content-Type", "text/plain");
    ajaxRequest.onreadystatechange = function () {
        if (ajaxRequest.readyState === 4) {
            //the request is completed, now check its status
            if (ajaxRequest.status === 200) {
                alert("Response from server: " + ajaxRequest.responseText);
            } else {
                console.log("Status error: " + ajaxRequest.status + ajaxRequest.getResponseHeader("Access-Control-Allow-Origin"));
            }
        } else {
            console.log("Ignored readyState: " + ajaxRequest.readyState);
        }
    }
    ajaxRequest.send();
}

function clearRequest(component_type) {
    let ajaxRequest = new XMLHttpRequest();
    let url = "http://127.0.0.1:5000/" + "clear_request/" + component_type + "/";
    ajaxRequest.open('GET', url, true);
    ajaxRequest.setRequestHeader("Content-Type", "text/plain");
    ajaxRequest.onreadystatechange = function () {
        if (ajaxRequest.readyState === 4) {
            //the request is completed, now check its status
            if (ajaxRequest.status === 200) {
                alert("Response from server: " + ajaxRequest.responseText);
            } else {
                console.log("Status error: " + ajaxRequest.status + ajaxRequest.getResponseHeader("Access-Control-Allow-Origin"));
            }
        } else {
            console.log("Ignored readyState: " + ajaxRequest.readyState);
        }
    }
    ajaxRequest.send();
}

function urlRequest(component_type) {
    let ajaxRequest = new XMLHttpRequest();
    let url = "http://127.0.0.1:5000/" + component_type + "/";
    ajaxRequest.open('GET', url, true);
    ajaxRequest.setRequestHeader("Content-Type", "text/plain");
    ajaxRequest.onreadystatechange = function () {
        if (ajaxRequest.readyState === 4) {
            //the request is completed, now check its status
            if (ajaxRequest.status === 200) {
                alert("Response from server: " + ajaxRequest.responseText);
            } else {
                console.log("Status error: " + ajaxRequest.status + ajaxRequest.getResponseHeader("Access-Control-Allow-Origin"));
            }
        } else {
            console.log("Ignored readyState: " + ajaxRequest.readyState);
        }
    }
    ajaxRequest.send();
}

class ResetSimulatorButton extends React.Component {
    /*
    return (
        <div className="d-grid gap-2">
            <Button variant="outline-danger" size="lg" onClick={resetOramSimulatorState}>
                Reset Simulator
            </Button>
        </div>
    );

     */
    constructor(props) {
        super(props);
        this.state = {
            reset_request: {
                number_of_oram: 1,
                tree_height: 10,
                oram_degree: 2,
                bucket_size: 32000,
                index_locality_cache: false,
                fill_grade: 16,
            },
        };
        this.handleResetRequestChange = this.handleResetRequestChange.bind(this);
        this.handleSubmit = this.handleSubmit.bind(this);
        this.computeOramByteSize = this.computeOramByteSize.bind(this);
    }

    computeOramByteSize() {
        const number_of_tree_nodes = Math.pow(this.state.reset_request.oram_degree, this.state.reset_request.tree_height) - 1;
        const new_size = ((this.state.reset_request.bucket_size * number_of_tree_nodes) * this.state.reset_request.number_of_oram);
        return new_size;
    }

    handleResetRequestChange(event) {
        const target = event.target;
        const name = target.name;
        if (target.type === 'checkbox') {
            const old_value = this.state.reset_request[name];
            this.setState(prevState => ({
                reset_request: {
                    ...prevState.reset_request,
                    [name]: !old_value
                }
            }));
        } else {
            const value = target.value;
            if (target.type === 'number') {
                this.setState(prevState => ({
                    reset_request: {
                        ...prevState.reset_request,
                        [name]: parseInt(value)
                    }
                }));
            } else {
                this.setState(prevState => ({
                    reset_request: {
                        ...prevState.reset_request,
                        [name]: value
                    }
                }));
            }
        }
    }

    print_bytes(bytes) {
        return bytes.toFixed(0) + " bytes (" + (bytes / Math.pow(10, 6)).toFixed(3) + " MB)";
    }

    handleSubmit(event) {
        const data = this.state.reset_request
        if (data.fill_grade === '') {
            alert('Please fill in the fill grade!');
        } else {
            const json_request = JSON.stringify(data);
            console.log(json_request);
            this.send_json(json_request, 'reset_request');
            alert('Your reset has been sent as a request.');
        }
        event.preventDefault();
    }

    send_json(json_data, url_suffix) {
        let ajaxRequest = new XMLHttpRequest();
        let url = "http://127.0.0.1:5000/" + url_suffix;
        ajaxRequest.open('POST', url, true);
        ajaxRequest.setRequestHeader("Content-Type", "application/json");
        ajaxRequest.onreadystatechange = function () {
            if (ajaxRequest.readyState === 4) {
                //the request is completed, now check its status
                if (ajaxRequest.status === 200) {
                    alert("Response from server: " + ajaxRequest.responseText);
                } else {
                    console.log("Status error: " + ajaxRequest.status + ajaxRequest.getResponseHeader("Access-Control-Allow-Origin"));
                }
            } else {
                console.log("Ignored readyState: " + ajaxRequest.readyState);
            }
        }
        ajaxRequest.send(json_data);
    }

    render() {
        const new_oram_size = this.computeOramByteSize();
        return (
            <Form onSubmit={this.handleSubmit}>
                <Row className="mb-3">
                    <Form.Group as={Col} >
                        <Form.Label>Index Locality Cache</Form.Label>
                        <Form.Check name="index_locality_cache" type="switch"
                                    checked={this.state.reset_request.index_locality_cache}
                                    onChange={this.handleResetRequestChange}/>
                    </Form.Group>
                    <Form.Group as={Col} controlId="formGridCity">
                        <Form.Label>Fill grade of OB-Tree</Form.Label>
                        <Form.Control name="fill_grade" type="number"
                                      value={this.state.reset_request.fill_grade}
                                      onChange={this.handleResetRequestChange}/>
                    </Form.Group>
                </Row>
                <Row className="mb-3">
                    <Form.Group as={Col} controlId="formGridCity">
                        <Form.Label>ORAM Degree</Form.Label>
                        <Form.Control name="oram_degree" type="number"
                                      value={this.state.reset_request.oram_degree}
                                      onChange={this.handleResetRequestChange}/>
                    </Form.Group>
                    <Form.Group as={Col} controlId="formGridCity">
                        <Form.Label>Number of ORAM Instances</Form.Label>
                        <Form.Control name="number_of_oram" type="number"
                                      value={this.state.reset_request.number_of_oram}
                                      onChange={this.handleResetRequestChange}/>
                    </Form.Group>
                    <Form.Group as={Col} controlId="formGridCity">
                        <Form.Label>ORAM Tree Height</Form.Label>
                        <Form.Control name="tree_height" type="number"
                                      value={this.state.reset_request.tree_height}
                                      onChange={this.handleResetRequestChange}/>
                    </Form.Group>
                    <Form.Group as={Col} controlId="formGridCity">
                        <Form.Label>Bucket Size (Bytes)</Form.Label>
                        <Form.Control name="bucket_size" type="number"
                                      value={this.state.reset_request.bucket_size}
                                      onChange={this.handleResetRequestChange}/>
                    </Form.Group>
                </Row>
                <div className="d-grid gap-2">
                    <p>ORAM size is: {this.print_bytes(new_oram_size)}</p>
                    <Button variant="warning" type="submit" size="lg">
                        Reset Simulator
                    </Button>
                </div>
            </Form>

        );
    }

}

class ExperimentRunnerForm extends React.Component {
    constructor(props) {
        super(props);
        this.state = {
            experiment_request: {
                experiment_id: 0,
                experiment_name: '',
                clear_stash_afterwards: false,
                index: 0,
                query_amount: 1000,
                query_batch_size: 20,
                query_type: 'INSERTION',
                oram_access_batch_size: 5,
                aggressive_caching: false,
                skew: false,
                pre_data_volume: 0,
                direct_eviction: false,
                locality_cache_direct_flush: false,
                min_matching_prefix_level: 5,
                oram_random_batch_size: false,
                bounded_locality_cache: 10,
                dummy_fill_oram_access_batch: false,
                keep_not_requested_in_buckets: 0.0,
            },
        };
        this.handleExpRequestChange = this.handleExpRequestChange.bind(this);
        this.handleSubmit = this.handleSubmit.bind(this);
    }

    handleExpRequestChange(event) {
        const target = event.target;
        const name = target.name;
        if (target.type === 'checkbox') {
            const old_value = this.state.experiment_request[name];
            this.setState(prevState => ({
                experiment_request: {
                    ...prevState.experiment_request,
                    [name]: !old_value
                }
            }));
        } else {
            let value = target.value;
            if (target.type === 'number') {
                if (isNaN(value)) {
                    value = 0;
                }
                this.setState(prevState => ({
                    experiment_request: {
                        ...prevState.experiment_request,
                        [name]: parseInt(value)
                    }
                }));
            } else {
                this.setState(prevState => ({
                    experiment_request: {
                        ...prevState.experiment_request,
                        [name]: value
                    }
                }));
            }
        }
    }

    handleSubmit(event) {
        this.setState(prevState => ({
            experiment_request: {
                ...prevState.experiment_request,
                "keep_not_requested_in_buckets": parseFloat(prevState.experiment_request.keep_not_requested_in_buckets)
            }
        }));

        const data = this.state.experiment_request
        if (data.experiment_name === '') {
            alert('Please fill in an experiment name!');
        } else {
            const json_request = JSON.stringify(data);
            console.log(json_request);
            this.send_json(json_request, 'experiment_runner');
            alert('Your experiment ' + data.experiment_name + ' has been sent as a request.');
        }
        event.preventDefault();
    }

    send_json(json_data, url_suffix) {
        let ajaxRequest = new XMLHttpRequest();
        let url = "http://127.0.0.1:5000/" + url_suffix;
        ajaxRequest.open('POST', url, true);
        ajaxRequest.setRequestHeader("Content-Type", "application/json");
        ajaxRequest.onreadystatechange = function () {
            if (ajaxRequest.readyState === 4) {
                //the request is completed, now check its status
                if (ajaxRequest.status === 200) {
                    alert("Response from server: " + ajaxRequest.responseText);
                } else {
                    console.log("Status error: " + ajaxRequest.status + ajaxRequest.getResponseHeader("Access-Control-Allow-Origin"));
                }
            } else {
                console.log("Ignored readyState: " + ajaxRequest.readyState);
            }
        }
        ajaxRequest.send(json_data);
    }

    render() {
        return (
            <Form onSubmit={this.handleSubmit}>
                <Form.Group className="mb-3" controlId="formGridAddress1">
                    <Form.Label>Experiment Name</Form.Label>
                    <Form.Control name="experiment_name" value={this.state.experiment_request.experiment_name}
                                  onChange={this.handleExpRequestChange}/>
                </Form.Group>
                <Form.Group className="mb-3" controlId="formGridCity">
                    <Form.Label>Index</Form.Label>
                    <Form.Control name="clear_stash_afterwards" value={this.state.experiment_request.index}
                                  onChange={this.handleExpRequestChange}/>
                </Form.Group>

                <Row className="mb-3">
                    <Form.Group as={Col} >
                        <Form.Label>Clear Stash Afterwards</Form.Label>
                        <Form.Check name="clear_stash_afterwards" type="switch"
                                    checked={this.state.experiment_request.clear_stash_afterwards}
                                    onChange={this.handleExpRequestChange}/>
                    </Form.Group>
                    <Form.Group as={Col} >
                        <Form.Label>Aggressive Locality Caching</Form.Label>
                        <Form.Check name="aggressive_caching" type="switch"
                                    checked={this.state.experiment_request.aggressive_caching}
                                    onChange={this.handleExpRequestChange}/>
                    </Form.Group>
                    <Form.Group as={Col} >
                        <Form.Label>Skew</Form.Label>
                        <Form.Check name="skew" type="switch"
                                    checked={this.state.experiment_request.skew}
                                    onChange={this.handleExpRequestChange}/>
                    </Form.Group>
                    <Form.Group as={Col} >
                        <Form.Label>Direct eviction (DE)</Form.Label>
                        <Form.Check name="direct_eviction" type="switch"
                                    checked={this.state.experiment_request.direct_eviction}
                                    onChange={this.handleExpRequestChange}/>
                    </Form.Group>
                    <Form.Group as={Col} >
                        <Form.Label>Locality Cache: Direct Flush</Form.Label>
                        <Form.Check name="locality_cache_direct_flush" type="switch"
                                    checked={this.state.experiment_request.locality_cache_direct_flush}
                                    onChange={this.handleExpRequestChange}/>
                    </Form.Group>
                    <Form.Group as={Col} >
                        <Form.Label>ORAM Random Batch Size</Form.Label>
                        <Form.Check name="oram_random_batch_size" type="switch"
                                    checked={this.state.experiment_request.oram_random_batch_size}
                                    onChange={this.handleExpRequestChange}/>
                    </Form.Group>
                    <Form.Group as={Col} >
                        <Form.Label>Fill ORAM Access Batch with dummies</Form.Label>
                        <Form.Check name="dummy_fill_oram_access_batch" type="switch"
                                    checked={this.state.experiment_request.dummy_fill_oram_access_batch}
                                    onChange={this.handleExpRequestChange}/>
                    </Form.Group>
                </Row>

                <Row className="mb-3">
                    <Form.Group as={Col} controlId="formGridCity">
                        <Form.Label>Query amount</Form.Label>
                        <Form.Control name="query_amount" type="number"
                                      value={this.state.experiment_request.query_amount}
                                      onChange={this.handleExpRequestChange}/>
                    </Form.Group>
                    <Form.Group as={Col} controlId="formGridCity">
                        <Form.Label>Data Pre-Volume</Form.Label>
                        <Form.Control name="pre_data_volume" type="number"
                                      value={this.state.experiment_request.pre_data_volume}
                                      onChange={this.handleExpRequestChange}/>
                    </Form.Group>
                    <Form.Group as={Col} controlId="formGridZip">
                        <Form.Label>Query batch size</Form.Label>
                        <Form.Control name="query_batch_size" type="number"
                                      value={this.state.experiment_request.query_batch_size}
                                      onChange={this.handleExpRequestChange}/>
                    </Form.Group>
                    <Form.Group as={Col} controlId="formGridZip">
                        <Form.Label>ORAM Access Batch Size</Form.Label>
                        <Form.Control name="oram_access_batch_size" type="number"
                                      value={this.state.experiment_request.oram_access_batch_size}
                                      onChange={this.handleExpRequestChange}/>
                    </Form.Group>
                </Row>

                <Row className="mb-3">
                    <Form.Group as={Col} controlId="formGridCity">
                        <Form.Label>Minimal Prefix</Form.Label>
                        <Form.Control name="min_matching_prefix_level" type="number"
                                      value={this.state.experiment_request.min_matching_prefix_level}
                                      onChange={this.handleExpRequestChange}/>
                    </Form.Group>
                    <Form.Group as={Col} controlId="formGridCity">
                        <Form.Label>Locality Cache Max</Form.Label>
                        <Form.Control name="bounded_locality_cache" type="number"
                                      value={this.state.experiment_request.bounded_locality_cache}
                                      onChange={this.handleExpRequestChange}/>
                    </Form.Group>
                    <Form.Group as={Col} controlId="formGridCity">
                        <Form.Label>Lazy Reshuffling</Form.Label>
                        <Form.Control name="keep_not_requested_in_buckets"
                                      value={this.state.experiment_request.keep_not_requested_in_buckets}
                                      onChange={this.handleExpRequestChange}/>
                    </Form.Group>
                    <Form.Group as={Col} >
                        <Form.Label>Query Type</Form.Label>
                        <Form.Select name="query_type" value={this.state.experiment_request.query_type}
                                     onChange={this.handleExpRequestChange}>
                            <option value="INSERTION">INSERTION</option>
                            <option value="SELECTION">SELECTION</option>
                            <option value="SELECT20INSERT80">SELECT20INSERT80</option>
                            <option value="SELECT80INSERT20">SELECT80INSERT20</option>
                            <option value="SELECT50INSERT50">SELECT50INSERT50</option>
                        </Form.Select>
                    </Form.Group>
                </Row>
                <div className="d-grid gap-2">
                    <Button variant="success" type="submit" size="lg">
                        Start Experiment
                    </Button>
                </div>
            </Form>

        );
    }
}

