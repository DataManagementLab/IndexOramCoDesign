import './App.css';
import React from "react";
import {BrowserRouter as Router, Route, Routes} from "react-router-dom";
import {Statistics} from "./Statistics";
import {NoMatch} from "./NoMatch";
import {Layout} from "./components/Layout";
import {NavigationBar} from "./components/NavigationBar";
import {Experiment} from "./Experiment";
import {Home} from "./Home";
import {Backup} from "./Backup";

function App() {
    return (
        <React.Fragment>
            <NavigationBar/>
            <Layout>
                <Router>
                    <Routes>
                        <Route exact path="/" element={<Home/>}/>
                        <Route exact path="/experiments" element={<Experiment/>}/>
                        <Route exact path="/statistics" element={<Statistics/>}/>
                        <Route exact path="/backup" element={<Backup/>}/>
                        <Route path="*" element={<NoMatch/>}/>
                    </Routes>
                </Router>
            </Layout>
        </React.Fragment>
    );
}

export default App;
