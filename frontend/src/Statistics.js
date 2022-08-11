import React, {Fragment, useRef} from "react";
import {Breadcrumb, Button, Card, Col, ListGroup, Row, Table} from "react-bootstrap";
import {ExperimentRequestTable} from "./components/ExperimentRequestTable";
import {WorkloadView} from "./components/WorkloadView";

export const Statistics = () => {
    return (
        <Row>
            <Col>
                <StatisticsViewer/>
            </Col>
        </Row>
    )
}

class StatisticsViewer extends React.Component {
    constructor(props) {
        super(props);
        this.state = {
            show_workload: false,
            experiment_id: 0
        };
    }

    selectExperiment = (expValueId) => {
        this.setState({
            show_workload: true,
            experiment_id: expValueId
        });
    }

    setShowWorkload(value) {
        this.setState(prevState => ({
            show_workload: value
        }));
    }

    render() {
        const show_workload = this.state.show_workload;
        return (
            <div>
                {show_workload ? (
                    <Fragment>
                        <Breadcrumb>
                            <Breadcrumb.Item onClick={() => this.setShowWorkload(false)}>All experiments</Breadcrumb.Item>
                            <Breadcrumb.Item active>Experiment { this.state.experiment_id }</Breadcrumb.Item>
                        </Breadcrumb>
                        <WorkloadView experiment_id={this.state.experiment_id}/>
                    </Fragment>
                ) : (
                    <ExperimentRequestTable onSelectExperiment={this.selectExperiment}/>
                )}
            </div>

        );
    }
}