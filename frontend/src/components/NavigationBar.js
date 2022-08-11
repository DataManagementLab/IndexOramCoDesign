import React from "react";
import {Nav, Navbar} from "react-bootstrap";
import styled from 'styled-components';
import Container from "react-bootstrap/Container";

const Styles = styled.div`
    a, .navbar-brand, .navbar-nav .nav-link {
        font-family: 'Arial';
    }
`;

export const NavigationBar = () => (
<Navbar bg="light" variant="light" className="mb-4">
    <Container>
        <Navbar.Brand href="/">Oblivious OLTP Simulator</Navbar.Brand>
        <Nav variant="pills" className="me-auto">
            <Nav.Link href="/experiments">Experiments</Nav.Link>
            <Nav.Link href="/statistics">Statistics</Nav.Link>
            <Nav.Link href="/backup">Backup</Nav.Link>
        </Nav>
    </Container>
</Navbar>
)