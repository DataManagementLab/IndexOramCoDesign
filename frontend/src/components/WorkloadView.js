import React from "react";
import {Button, Card, ListGroup, Col, Row, Table, Badge, Stack, Figure} from "react-bootstrap";
import {ExperimentRequestTable} from "./ExperimentRequestTable";

export class WorkloadView extends React.Component {
    constructor(props) {
        super(props);
        this.state = {
            enclave_stats: {
                experiment_id: 0,

                index_locality_cache: false,
                obt_fill_grade: 0,

                oram_reads: 0,
                oram_read_time: 0,
                oram_writes: 0,
                oram_write_time: 0,
                time_evict_into_oram_batch_from_packet_stash: 0,

                workload_time: 0,

                time_evict_bottom_up: 0,
                time_split_node: 0,
                time_cast_split_to_parent: 0,

                times_node_found_in_locality_cache: 0,
                times_slot_found_in_locality_cache: 0,
                times_node_originally_from_locality_cache: 0,
                times_slot_originally_from_locality_cache: 0,

                times_more_than_one_packet: 0,
                evicted_packets: 0,
                total_node_evictions: 0,
                total_node_traversal_visits: 0,
                requested_oram_leaves: 0,

                number_packets_requested_from_oram: 0,
                number_packets_found_in_stash: 0,
                number_nodes_found_in_node_cache: 0,
                number_slots_found_in_slot_cache: 0,

                insert_packet_to_stash_time: 0,
                insert_packet_of_bucket_to_stash_time: 0,
                iter_buckets_from_oram_time: 0,
                time_clear_index_locality_cache_to_packet_stash: 0,
                time_flush_packets_of_query_id_to_stash: 0,
                time_iterate_buckets_for_locality_cache: 0,

                time_transform_fragments_to_obt_node: 0,
                time_transform_fragments_to_obt_slot: 0,

                time_serialize_obtree_node: 0,
                time_decompress_sql_data_type: 0,
                time_transform_bytes_to_oram_packets: 0,
                time_transform_buckets_to_bucket_contents: 0,
                time_transform_bucket_contents_to_buckets: 0,
                time_byte_range_to_sql_data_types: 0,

                generated_data_byte_size: 0,
            },
            enclave_additional_stats: {
                experiment_id: 0,
                max_stash_packet_amount: 0.0,
                max_stash_byte_size: 0.0,
                average_stash_packet_amount: 0.0,
                average_stash_byte_size: 0.0,
                max_nodecache_packet_amount: 0.0,
                max_nodecache_byte_size: 0.0,
                average_nodecache_packet_amount: 0.0,
                average_nodecache_byte_size: 0.0,
                max_localitycache_byte_size: 0.0,
                max_localitycache_packet_amount: 0.0,
                average_localitycache_byte_size: 0.0,
                average_localitycache_packet_amount: 0.0,
                average_batch_size: 0.0,
                max_batch_size: 0.0,
            },
            oram_config: {
                experiment_id: 0,
                number_of_oram: 0,
                tree_height: 0,
                oram_degree: 0,
                bucket_size: 0,
                oram_byte_size: 0,
                oram_mb_size: 0,
            },
            exp_request: {
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
            }
        };
        this.refreshContent = this.refreshContent.bind(this);
        this.ns_into_ms = this.ns_into_ms.bind(this);
    }

    refreshContent() {
        console.log("Refresh of WorkloadView!");
        if (this.state.experiment_id !== this.props.experiment_id) {
            fetch('http://127.0.0.1:5000/json/filter/enclave_stats/' + this.props.experiment_id)
                .then(response => response.json())
                .then(data => {
                    this.setState({
                        enclave_stats: data[0]
                    })
                });
            fetch('http://127.0.0.1:5000/json/filter/enclave_additional_stats/' + this.props.experiment_id)
                .then(response => response.json())
                .then(data => {
                    this.setState({
                        enclave_additional_stats: data[0]
                    })
                });
            fetch('http://127.0.0.1:5000/json/filter/oram_configs/' + this.props.experiment_id)
                .then(response => response.json())
                .then(data => {
                    this.setState({
                        oram_config: data[0]
                    })
                });
            fetch('http://127.0.0.1:5000/json/filter/exp_request/' + this.props.experiment_id)
                .then(response => response.json())
                .then(data => {
                    this.setState({
                        exp_request: data[0]
                    })
                });
        }
    }

    componentDidMount() {
        this.refreshContent()
    }

    componentDidUpdate(prevProps) {
        // Typical usage (don't forget to compare props):
        if (this.props.experiment_id !== prevProps.experiment_id) {
            this.refreshContent();
        }
    }


    ns_into_ms(time_in_ns) {
        const time_in_ms = time_in_ns / 1000000;
        const time_in_s = time_in_ms / 1000;
        return (time_in_ms.toFixed(3) + " ms (" + time_in_s.toFixed(2) + " s)");
    }

    print_bytes(bytes) {
        return bytes.toFixed(0) + " (" + (bytes / Math.pow(10, 6)).toFixed(3) + " MB)";
    }

    /*
    componentWillReceiveProps(props) {
        this.setState({ experiment_id: props.experiment_id });
        this.refreshContent();
    }
     */

    render() {
        return (
            <Card>
                <Card.Header>
                    <Row>
                        <Col>
                            ID: {this.props.experiment_id}
                        </Col>
                        <Col xs={2}>
                            <div className="d-grid gap-2">
                                <Button variant="outline-info" size="sm" onClick={this.refreshContent}>
                                    Refresh
                                </Button>
                            </div>
                        </Col>
                    </Row>
                </Card.Header>
                <Card.Body>
                    <Row className="mt-3">
                        <Col>
                            <ExperimentRequestCard exp_request={this.state.exp_request}/>
                        </Col>
                        <Col>
                            <Row>
                                <StatItem prefix="Index Locality Cache" border="dark"
                                          value={this.state.enclave_stats.index_locality_cache ? "true" : "false"}/>
                            </Row>
                            <Row className="mt-3">
                                <StatItem prefix="OBT Fill Grade" border="dark"
                                          value={this.state.enclave_stats.obt_fill_grade}/>
                            </Row>
                        </Col>
                    </Row>
                    <Row className="mt-3">
                        <Col>
                            <StatItem prefix="ORAM instances" border="info"
                                      value={this.state.oram_config.number_of_oram}/>
                        </Col>
                        <Col>
                            <StatItem prefix="ORAM Degree" border="info"
                                      value={this.state.oram_config.oram_degree}/>
                        </Col>
                        <Col>
                            <StatItem prefix="ORAM Tree Height" border="info"
                                      value={this.state.oram_config.tree_height}/>
                        </Col>
                        <Col>
                            <StatItem prefix="ORAM Bucket Size" border="info"
                                      value={this.state.oram_config.bucket_size}/>
                        </Col>
                        <Col>
                            <StatItem prefix="ORAM Byte Size" border="info"
                                      value={this.print_bytes(this.state.oram_config.oram_byte_size)}/>
                        </Col>
                    </Row>
                    <Row className="mt-3">
                        <Col>
                            <StatItem prefix="ORAM Reads" border="success"
                                      value={this.state.enclave_stats.oram_reads}/>
                        </Col>
                        <Col>
                            <StatItem prefix="ORAM Read Time" border="success"
                                      value={this.ns_into_ms(this.state.enclave_stats.oram_read_time)}/>
                        </Col>
                        <Col>
                            <StatItem prefix="ORAM Writes" border="success"
                                      value={this.state.enclave_stats.oram_writes}/>
                        </Col>
                        <Col>
                            <StatItem prefix="ORAM Write Time" border="success"
                                      value={this.ns_into_ms(this.state.enclave_stats.oram_write_time)}/>
                        </Col>
                    </Row>
                    <Row className="mt-3">
                        <Col>
                            <StatItem prefix="Workload Time" border="primary"
                                      value={this.ns_into_ms(this.state.enclave_stats.workload_time)}
                            />
                        </Col>
                    </Row>
                    <Row className="mt-3">
                        <Col>
                            <StatItem prefix="Eviction From Stash" border="secondary"
                                      value={this.ns_into_ms(this.state.enclave_stats.time_evict_into_oram_batch_from_packet_stash)}
                            />
                        </Col>
                        <Col>
                            <StatItem prefix="Evict Bottum Up" border="secondary"
                                      value={this.ns_into_ms(this.state.enclave_stats.time_evict_bottom_up)}
                            />
                        </Col>
                        <Col>
                            <StatItem prefix="Split Node" border="secondary"
                                      value={this.ns_into_ms(this.state.enclave_stats.time_split_node)}/>
                        </Col>
                        <Col>
                            <StatItem prefix="Cast Split To Parent" border="secondary"
                                      value={this.ns_into_ms(this.state.enclave_stats.time_cast_split_to_parent)}
                            />
                        </Col>
                    </Row>
                    <Row className="mt-3">
                        <Col>
                            <StatItem prefix="Node found in Locality Cache" border="success"
                                      value={this.state.enclave_stats.times_node_found_in_locality_cache}/>
                        </Col>
                        <Col>
                            <StatItem prefix="Slot found in Locality Cache" border="success"
                                      value={this.state.enclave_stats.times_slot_found_in_locality_cache}/>
                        </Col>
                        <Col>
                            <StatItem prefix="Node originally from Locality Cache" border="success"
                                      value={this.state.enclave_stats.times_node_originally_from_locality_cache}/>
                        </Col>
                        <Col>
                            <StatItem prefix="Slot originally from Locality Cache" border="success"
                                      value={this.state.enclave_stats.times_slot_originally_from_locality_cache}/>
                        </Col>
                        <Col>
                            <StatItem prefix="Serialization to more than one packet" border="secondary"
                                      value={this.state.enclave_stats.times_more_than_one_packet}/>
                        </Col>
                    </Row>
                    <Row className="mt-3">
                        <Col>
                            <StatItem prefix="Evicted Packets" border="secondary"
                                      value={this.state.enclave_stats.evicted_packets}/>
                        </Col>
                        <Col>
                            <StatItem prefix="total_node_evictions" border="secondary"
                                      value={this.state.enclave_stats.total_node_evictions}/>
                        </Col>
                        <Col>
                            <StatItem prefix="total_node_traversal_visits" border="secondary"
                                      value={this.state.enclave_stats.total_node_traversal_visits}/>
                        </Col>
                        <Col>
                            <StatItem prefix="Requested ORAM Leaves" border="secondary"
                                      value={this.state.enclave_stats.requested_oram_leaves}/>
                        </Col>
                    </Row>
                    <Row className="mt-3">
                        <Col>
                            <StatItem prefix="Total requested ORAM Packets" border="secondary"
                                      value={this.state.enclave_stats.number_packets_requested_from_oram}/>
                        </Col>
                        <Col>
                            <StatItem prefix="number_packets_found_in_stash" border="secondary"
                                      value={this.state.enclave_stats.number_packets_found_in_stash}/>
                        </Col>
                        <Col>
                            <StatItem prefix="Nodes found locally" border="secondary"
                                      value={this.state.enclave_stats.number_nodes_found_in_node_cache}/>
                        </Col>
                        <Col>
                            <StatItem prefix="Slots found locally" border="secondary"
                                      value={this.state.enclave_stats.number_slots_found_in_slot_cache}/>
                        </Col>
                        <Col>
                            <StatItem prefix="generated_data_byte_size" border="secondary"
                                      value={this.print_bytes(this.state.enclave_stats.generated_data_byte_size)}/>
                        </Col>
                    </Row>
                    <Row className="mt-3">
                        <Col>
                            <StatItem prefix="Iteration of Buckets from ORAM" border="secondary"
                                      value={this.ns_into_ms(this.state.enclave_stats.iter_buckets_from_oram_time)}
                            />
                        </Col>
                        <Col>
                            <StatItem prefix="Bucket Iteration for Locality Cache" border="secondary"
                                      value={this.ns_into_ms(this.state.enclave_stats.time_iterate_buckets_for_locality_cache)}
                            />
                        </Col>
                    </Row>
                    <Row className="mt-3">
                        <Col>
                            <StatItem prefix="Packet To Stash Insertion" border="secondary"
                                      value={this.ns_into_ms(this.state.enclave_stats.insert_packet_to_stash_time)}
                            />
                        </Col>
                        <Col>
                            <StatItem prefix="insert_packet_of_bucket_to_stash_time" border="secondary"
                                      value={this.ns_into_ms(this.state.enclave_stats.insert_packet_of_bucket_to_stash_time)}
                            />
                        </Col>
                        <Col>
                            <StatItem prefix="Clear Index Locality Cache" border="secondary"
                                      value={this.ns_into_ms(this.state.enclave_stats.time_clear_index_locality_cache_to_packet_stash)}
                            />
                        </Col>
                        <Col>
                            <StatItem prefix="Query Flush Index Locality Cache" border="secondary"
                                      value={this.ns_into_ms(this.state.enclave_stats.time_flush_packets_of_query_id_to_stash)}
                            />
                        </Col>
                    </Row>
                    <Row className="mt-3">
                        <Col>
                            <StatItem prefix="Bytes to OB-Tree Node" border="secondary"
                                      value={this.ns_into_ms(this.state.enclave_stats.time_transform_fragments_to_obt_node)}
                            />
                        </Col>
                        <Col>
                            <StatItem prefix="Bytes to OB-Tree Slot" border="secondary"
                                      value={this.ns_into_ms(this.state.enclave_stats.time_transform_fragments_to_obt_slot)}
                            />
                        </Col>
                        <Col>
                            <StatItem prefix="Packet Locality Byte Range to SQL Data Types" border="secondary"
                                      value={this.ns_into_ms(this.state.enclave_stats.time_byte_range_to_sql_data_types)}
                            />
                        </Col>
                    </Row>
                    <Row className="mt-3">
                        <Col>
                            <StatItem prefix="Serialize Nodes" border="secondary"
                                      value={this.ns_into_ms(this.state.enclave_stats.time_serialize_obtree_node)}
                            />
                        </Col>
                        <Col>
                            <StatItem prefix="Decompression of SQL Types" border="secondary"
                                      value={this.ns_into_ms(this.state.enclave_stats.time_decompress_sql_data_type)}
                            />
                        </Col>
                        <Col>
                            <StatItem prefix="Bytes To ORAM Packets" border="secondary"
                                      value={this.ns_into_ms(this.state.enclave_stats.time_transform_bytes_to_oram_packets)}
                            />
                        </Col>
                    </Row>
                    <Row className="mt-3">
                        <Col>
                            <StatItem prefix="Buckets To BucketContents (Decryption)" border="secondary"
                                      value={this.ns_into_ms(this.state.enclave_stats.time_transform_buckets_to_bucket_contents)}
                            />
                        </Col>
                        <Col>
                            <StatItem prefix="BucketContents To Buckets (Encryption)" border="secondary"
                                      value={this.ns_into_ms(this.state.enclave_stats.time_transform_bucket_contents_to_buckets)}
                            />
                        </Col>
                    </Row>
                    <Row className="mt-3">
                        <Col>
                            <StatItem prefix="max_localitycache_packet_amount" border="secondary"
                                      value={this.state.enclave_additional_stats.max_localitycache_packet_amount}/>
                        </Col>
                        <Col>
                            <StatItem prefix="max_localitycache_byte_size" border="secondary"
                                      value={this.print_bytes(this.state.enclave_additional_stats.max_localitycache_byte_size)}/>
                        </Col>
                        <Col>
                            <StatItem prefix="average_localitycache_packet_amount" border="secondary"
                                      value={this.state.enclave_additional_stats.average_localitycache_packet_amount}/>
                        </Col>
                        <Col>
                            <StatItem prefix="average_localitycache_byte_size" border="secondary"
                                      value={this.print_bytes(this.state.enclave_additional_stats.average_localitycache_byte_size)}/>
                        </Col>
                    </Row>
                    <Row className="mt-3">
                        <Col>
                            <StatItem prefix="max_stash_packet_amount" border="secondary"
                                      value={this.state.enclave_additional_stats.max_stash_packet_amount}/>
                        </Col>
                        <Col>
                            <StatItem prefix="max_stash_byte_size" border="secondary"
                                      value={this.print_bytes(this.state.enclave_additional_stats.max_stash_byte_size)}/>
                        </Col>
                        <Col>
                            <StatItem prefix="average_stash_packet_amount" border="secondary"
                                      value={this.state.enclave_additional_stats.average_stash_packet_amount}/>
                        </Col>
                        <Col>
                            <StatItem prefix="average_stash_byte_size" border="secondary"
                                      value={this.print_bytes(this.state.enclave_additional_stats.average_stash_byte_size)}/>
                        </Col>
                    </Row>
                    <Row className="mt-3">
                        <Col>
                            <StatItem prefix="max_nodecache_packet_amount" border="secondary"
                                      value={this.state.enclave_additional_stats.max_nodecache_packet_amount}/>
                        </Col>
                        <Col>
                            <StatItem prefix="max_nodecache_byte_size" border="secondary"
                                      value={this.print_bytes(this.state.enclave_additional_stats.max_nodecache_byte_size)}/>
                        </Col>
                        <Col>
                            <StatItem prefix="average_nodecache_packet_amount" border="secondary"
                                      value={this.state.enclave_additional_stats.average_nodecache_packet_amount}/>
                        </Col>
                        <Col>
                            <StatItem prefix="average_nodecache_byte_size" border="secondary"
                                      value={this.print_bytes(this.state.enclave_additional_stats.average_nodecache_byte_size)}/>
                        </Col>
                    </Row>
                    <Row className="mt-3">
                        <Col>
                            <StatItem prefix="average_batch_size" border="secondary"
                                      value={this.state.enclave_additional_stats.average_batch_size}/>
                        </Col>
                        <Col>
                            <StatItem prefix="max_batch_size" border="secondary"
                                      value={this.state.enclave_additional_stats.max_batch_size}/>
                        </Col>
                    </Row>
                    <Row className="mt-3 justify-content-md-center">
                        <Col xs={12} sm={10} lg={8}>
                            <PlotFigure filename="accessed_positions" experiment_id={this.props.experiment_id}
                                        title="Accessed ORAM positions"
                                        description="Number of total position accesses per leaf (averaged by number of ORAM instances)"/>
                        </Col>
                    </Row>
                    <Row className="mt-3 justify-content-md-center">
                        <Col xs={12} sm={10} lg={8}>
                            <PlotFigure filename="batch_size_chrono" experiment_id={this.props.experiment_id}
                                        title="ORAM Batches over time"
                                        description="How the ORAM access batch size behaves over time"/>
                        </Col>
                    </Row>
                    <Row className="mt-3 justify-content-md-center">
                        <Col xs={12} sm={10} lg={8}>
                            <PlotFigure filename="stash_packet_amount" experiment_id={this.props.experiment_id}
                                        title=""
                                        description="How the stash_packet_amount behaves over time"/>
                        </Col>
                    </Row>
                    <Row className="mt-3 justify-content-md-center">
                        <Col xs={12} sm={10} lg={8}>
                            <PlotFigure filename="stash_byte_size" experiment_id={this.props.experiment_id}
                                        title=""
                                        description="How the size behaves over time"/>
                        </Col>
                    </Row>
                    <Row className="mt-3 justify-content-md-center">
                        <Col xs={12} sm={10} lg={8}>
                            <PlotFigure filename="node_cache_amount" experiment_id={this.props.experiment_id}
                                        title=""
                                        description="How the node_cache_amount behaves over time"/>
                        </Col>
                    </Row>
                    <Row className="mt-3 justify-content-md-center">
                        <Col xs={12} sm={10} lg={8}>
                            <PlotFigure filename="node_cache_byte_size" experiment_id={this.props.experiment_id}
                                        title=""
                                        description="How the node_cache_byte_size behaves over time"/>
                        </Col>
                    </Row>
                    <Row className="mt-3 justify-content-md-center">
                        <Col xs={12} sm={10} lg={8}>
                            <PlotFigure filename="slot_cache_amount" experiment_id={this.props.experiment_id}
                                        title=""
                                        description="How the slot_cache_amount behaves over time"/>
                        </Col>
                    </Row>
                    <Row className="mt-3 justify-content-md-center">
                        <Col xs={12} sm={10} lg={8}>
                            <PlotFigure filename="slot_cache_byte_size" experiment_id={this.props.experiment_id}
                                        title=""
                                        description="How the slot_cache_byte_size behaves over time"/>
                        </Col>
                    </Row>
                    <Row className="mt-3 justify-content-md-center">
                        <Col xs={12} sm={10} lg={8}>
                            <PlotFigure filename="locality_cache_amount" experiment_id={this.props.experiment_id}
                                        title=""
                                        description="How the locality_cache_amount behaves over time"/>
                        </Col>
                    </Row>
                    <Row className="mt-3 justify-content-md-center">
                        <Col xs={12} sm={10} lg={8}>
                            <PlotFigure filename="locality_cache_byte_size" experiment_id={this.props.experiment_id}
                                        title=""
                                        description="How the locality_cache_byte_size behaves over time"/>
                        </Col>
                    </Row>
                    <Row className="mt-3 justify-content-md-center">
                        <Col xs={12} sm={10} lg={8}>
                            <PlotFigure filename="evicted_packets_over_time" experiment_id={this.props.experiment_id}
                                        title=""
                                        description="evicted_packets_over_time"/>
                        </Col>
                    </Row>
                    <Row className="mt-3 justify-content-md-center">
                        <Col xs={12} sm={10} lg={8}>
                            <PlotFigure filename="free_oram_space_in_batch_over_time"
                                        experiment_id={this.props.experiment_id}
                                        title=""
                                        description="free_oram_space_in_batch_over_time"/>
                        </Col>
                    </Row>
                    <Row className="mt-3 justify-content-md-center">
                        <Col xs={12} sm={10} lg={8}>
                            <PlotFigure filename="stash_packet_max_size" experiment_id={this.props.experiment_id}
                                        title=""
                                        description="stash_packet_max_size"/>
                        </Col>
                    </Row>
                    <Row className="mt-3 justify-content-md-center">
                        <Col xs={12} sm={10} lg={8}>
                            <PlotFigure filename="stash_packet_average_size" experiment_id={this.props.experiment_id}
                                        title=""
                                        description="stash_packet_average_size"/>
                        </Col>
                    </Row>

                </Card.Body>
            </Card>

        );
    }

}

function ExperimentRequestCard(props) {
    return (
        <Card>
            <Card.Body>
                <Card.Title>{props.exp_request.experiment_name}</Card.Title>
                <Card.Text>
                    Query Amount: {props.exp_request.query_amount} <br/>
                    Query Batch Size: {props.exp_request.query_batch_size} <br/>
                    ORAM Access Batch Size: {props.exp_request.oram_access_batch_size} <br/>
                    Skew: {props.exp_request.skew ? "true" : "false"} <br/>
                    Data inserted before workload: {props.exp_request.pre_data_volume} <br/>
                    Direct Eviction for Read Queries: {props.exp_request.direct_eviction ? "true" : "false"} <br/>
                    Locality Cache Direct Flush: {props.exp_request.locality_cache_direct_flush ? "true" : "false"}
                    <br/>
                    Min. Matching Prefix Level: {props.exp_request.min_matching_prefix_level} <br/>
                    Bounded Locality Cache: {props.exp_request.bounded_locality_cache} <br/>
                    Dummy Fill ORAM Access Batch: {props.exp_request.dummy_fill_oram_access_batch ? "true" : "false"}
                    <br/>
                    Aggressive Caching: {props.exp_request.aggressive_caching ? "true" : "false"} <br/>
                    Query Type: {props.exp_request.query_type} <br/>
                    Keep not requested packets in buckets: {props.exp_request.keep_not_requested_in_buckets} <br/>
                </Card.Text>
            </Card.Body>
        </Card>
    );
}

function StatItem(props) {
    return (
        <ListGroup className="text-center">
            <ListGroup.Item><h5 className="m-0">{props.prefix}</h5></ListGroup.Item>
            <ListGroup.Item><h3 className="m-0"><Badge bg={props.border}>{props.value}</Badge> {props.suffix}</h3>
            </ListGroup.Item>
        </ListGroup>
    );
}

function PlotFigure(props) {
    const link = "http://localhost:5000/plots/" + props.filename + "/" + props.experiment_id;
    return (
        <Card className="w-100">
            <Card.Img variant="top" src={link} alt="Figure cannot be loaded"/>
            <Card.Body>
                <Card.Title>{props.title}</Card.Title>
                <Card.Text>
                    {props.description}
                </Card.Text>
            </Card.Body>
        </Card>
    );
}