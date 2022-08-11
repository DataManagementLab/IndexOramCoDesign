import React from "react";
import {Button, Card, Col, Form, Row, Stack} from "react-bootstrap";
import Container from "react-bootstrap/Container";

export const Backup = () => (
    <Container>
        <Row>
            <Col>
                <Card>
                    <Card.Header>Backups</Card.Header>
                    <Card.Body>
                        <Card.Title>Please choose the needed variables.</Card.Title>
                        <BackupForm/>
                    </Card.Body>
                </Card>
            </Col>
        </Row>
    </Container>
)

class BackupForm extends React.Component {
    constructor(props) {
        super(props);
        this.state = {
            backup_request: {
                restore: false,
                backup_name: ""
            }
        };
        this.handleChangeForm = this.handleChangeForm.bind(this);
        this.handleSubmit = this.handleSubmit.bind(this);
    }

    handleChangeForm(event) {
        const target = event.target;
        const name = target.name;
        if (target.type === 'checkbox') {
            const old_value = this.state.backup_request[name];
            this.setState(prevState => ({
                backup_request: {
                    ...prevState.backup_request,
                    [name]: !old_value
                }
            }));
        } else {
            const value = target.value;
            if (target.type === 'number') {
                this.setState(prevState => ({
                    backup_request: {
                        ...prevState.backup_request,
                        [name]: parseInt(value)
                    }
                }));
            } else {
                this.setState(prevState => ({
                    backup_request: {
                        ...prevState.backup_request,
                        [name]: value
                    }
                }));
            }
        }
    }

    handleSubmit(event) {
        const backup_name = this.state.backup_request.backup_name
        if (backup_name === '') {
            alert('Please fill in the backup_name');
            return;
        }

        let url = "http://127.0.0.1:5000/";
        if (this.state.backup_request.restore) {
            url = url + "restore_backup_request/";
        } else {
            url = url + "backup_request/";
        }
        url = url + backup_name + "/";

        let ajaxRequest = new XMLHttpRequest();
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
        event.preventDefault();
    }

    render() {
        return (
            <Row>
                <Form onSubmit={this.handleSubmit}>
                    <Row className="mb-3">
                        <Form.Group as={Col} >
                            <Form.Label>restore</Form.Label>
                            <Form.Check name="restore" type="switch"
                                        checked={this.state.backup_request.restore}
                                        onChange={this.handleChangeForm}/>
                        </Form.Group>
                        <Form.Group as={Col} controlId="formGridCity">
                            <Form.Label>backup_name</Form.Label>
                            <Form.Control name="backup_name" type="text"
                                          value={this.state.backup_request.backup_name}
                                          onChange={this.handleChangeForm}/>
                        </Form.Group>
                    </Row>
                    <Row>
                        <Button variant="warning" type="submit" size="lg">
                            Backup Request
                        </Button>
                    </Row>
                </Form>
            </Row>
        );
    }

}

