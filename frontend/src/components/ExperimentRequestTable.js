import React from "react";
import {Button, Card, Col, Row, Table} from "react-bootstrap";

export class ExperimentRequestTable extends React.Component {
    constructor(props) {
        super(props);
        this.state = {
            experiment_requests: [],
        };
        this.refreshContent = this.refreshContent.bind(this);
        this.clickOnExperiment = this.clickOnExperiment.bind(this);
    }

    refreshContent() {
        console.log("Refresh of ExperimentTable!");
        fetch('http://127.0.0.1:5000/json/exp_request')
            .then(response => response.json())
            .then(data => {
                this.setState({
                    experiment_requests: data
                })
            });
    }

    componentDidMount() {
        this.refreshContent()
    }

    clickOnExperiment(experiment_id) {
        this.props.onSelectExperiment(experiment_id);
    }

    render() {
        return (
            <Card>
                <Card.Header>
                    <Row>
                        <Col>
                            All experiments
                        </Col>
                        <Col xs={2}>
                            <div className="d-grid gap-2">
                                <Button variant="outline-info" size="sm" onClick={() => this.refreshContent()}>
                                    Refresh
                                </Button>
                            </div>
                        </Col>
                    </Row>
                </Card.Header>
                <Card.Body>
                    <div>
                        <Table responsive className="table table-striped">
                            <thead>
                            <tr>
                                <th>Select</th>
                                <th>Experiment Name</th>
                                <th>Query Amount</th>
                                <th>Query Batch Size</th>
                                <th>ORAM Access Batch Size</th>
                                <th>Aggressive Caching</th>
                                <th>Skew</th>
                                <th>Pre-Data Volume</th>
                                <th>Direct Eviction</th>
                                <th>Locality Cache Direct Flush</th>
                                <th>Min Matching Prefix Level</th>
                                <th>ORAM Randomize Batch Size</th>
                                <th>Bounded Locality Cache</th>
                                <th>Fill ORAM Access Batch with Dummies</th>
                                <th>Keep not requested packets in buckets</th>
                                <th>Query Type</th>
                                <th>Clear Stash Afterwards</th>
                                <th>Index</th>
                            </tr>
                            </thead>
                            <tbody>
                            {
                                this.state.experiment_requests.map((row) => (
                                    <tr key={row.experiment_id}>
                                        <td><Button variant="outline-primary"
                                                    onClick={() => this.clickOnExperiment(row.experiment_id)}>Select</Button>
                                        </td>
                                        <td>{row.experiment_name} ({row.experiment_id})</td>
                                        <td>{row.query_amount}</td>
                                        <td>{row.query_batch_size}</td>
                                        <td>{row.oram_access_batch_size}</td>
                                        <td>{row.aggressive_caching ? "true" : "false"}</td>
                                        <td>{row.skew ? "true / SK" : "false"}</td>
                                        <td>{row.pre_data_volume}</td>
                                        <td>{row.direct_eviction ? "true / DE" : "false / FE"}</td>
                                        <td>{row.locality_cache_direct_flush ? "true" : "false"}</td>
                                        <td>{row.min_matching_prefix_level}</td>
                                        <td>{row.oram_random_batch_size ? "true" : "false"}</td>
                                        <td>{row.bounded_locality_cache}</td>
                                        <td>{row.dummy_fill_oram_access_batch ? "true" : "false"}</td>
                                        <td>{row.keep_not_requested_in_buckets}</td>
                                        <td>{row.query_type}</td>
                                        <td>{row.clear_stash_afterwards ? "true" : "false"}</td>
                                        <td>{row.index}</td>
                                    </tr>
                                ))
                            }
                            </tbody>
                        </Table>
                    </div>
                </Card.Body>
                <Card.Footer className="text-muted">
                </Card.Footer>
            </Card>
        );
    }
}