use crate::logger::log_error;
use crate::{ACCESSED_POSITIONS, BATCH_SIZE_CHRONO};
use plotters::coord::ranged1d::SegmentedCoord;
use plotters::coord::types::{RangedCoordf64, RangedCoordi32};
use plotters::coord::Shift;
use plotters::prelude::*;
use std::ops::Div;

pub fn plot_accessed_positions(number_of_oram: usize, mut path: String, experiment_id: u64) -> f64 {
    path.push_str(&format!(
        "accessed_positions_histogram_{}.png",
        experiment_id
    ));

    let accessed_positions = ACCESSED_POSITIONS.lock().unwrap();
    let mut y_data = vec![0.0f64; accessed_positions.len() - 1];
    let mut upper_range: f64 = 0.0;
    {
        let number_of_orams = number_of_oram as f64;
        for pos in 1..accessed_positions.len() {
            y_data[pos - 1] = (accessed_positions[pos] as f64) / number_of_orams;
            if y_data[pos - 1] > upper_range {
                upper_range = y_data[pos - 1];
            }
        }
    }
    drop(accessed_positions);

    draw_f64_histogram(
        &y_data,
        path.as_str(),
        upper_range,
        "Number of accesses per position (average of all ORAMs)",
        "Position/Leaf",
        "Count",
        PlotColor::BLUE,
    );

    let mut accessed_positions = ACCESSED_POSITIONS.lock().unwrap();
    for pos in 0..accessed_positions.len() {
        accessed_positions[pos] = 0;
    }

    upper_range
}

pub enum PlotColor {
    BLUE,
    RED,
}

fn draw_f64_histogram(
    y_data: &Vec<f64>,
    path: &str,
    upper_range: f64,
    caption: &str,
    x_desc: &str,
    y_desc: &str,
    color: PlotColor,
) {
    let root_area = BitMapBackend::new(&path, (1920, 1080)).into_drawing_area();
    root_area.fill(&WHITE).unwrap();
    let root_area = root_area.margin(40, 40, 40, 40);
    let mut ctx = ChartBuilder::on(&root_area)
        .set_label_area_size(LabelAreaPosition::Left, 40)
        .set_label_area_size(LabelAreaPosition::Bottom, 40)
        .caption(caption, ("Monospace", 30))
        .build_cartesian_2d((0..(y_data.len())).into_segmented(), 0.0..upper_range)
        .unwrap();
    ctx.configure_mesh()
        .y_desc(y_desc)
        .x_desc(x_desc)
        .axis_desc_style(("Monospace", 15))
        .draw()
        .unwrap();
    ctx.draw_series((0..).zip(y_data.iter()).map(|(x, y)| {
        let color = match color {
            PlotColor::BLUE => BLUE.filled(),
            PlotColor::RED => RED.filled(),
        };
        let x0 = SegmentValue::Exact(x);
        let x1 = SegmentValue::Exact(x + 1);
        let mut bar = Rectangle::new([(x0, 0.0), (x1, *y)], color);
        bar.set_margin(0, 0, 5, 5);
        bar
    }))
    .unwrap();
    match root_area.present() {
        Ok(_) => {
            println!("Result has been saved to {}", &path);
        }
        Err(err) => {
            log_error(&format!("Unable to write result to file, please make sure 'plots' dir exists under current dir: {} with file {}", err.to_string(), &path));
        }
    }
}

pub fn plot_and_empty_f64_data_vec(
    mut path: String,
    data: &mut Vec<f64>,
    file_name: &str,
    experiment_id: u64,
    caption: &str,
    x_desc: &str,
    y_desc: &str,
    color: PlotColor,
) -> (f64, f64) {
    path.push_str(&format!("{}_{}.png", file_name, experiment_id));

    let mut sum: f64 = 0.0;
    let mut upper_range: f64 = 0.0;
    {
        for i in 0..data.len() {
            sum += data[i];
            if data[i] > upper_range {
                upper_range = data[i];
            }
        }
    }
    let len = data.len() as f64;

    draw_f64_histogram(
        &data,
        path.as_str(),
        upper_range,
        caption,
        x_desc,
        y_desc,
        color,
    );

    data.truncate(0);

    (upper_range, (sum.div(len)))
}

fn draw_f64_function(y_data: &Vec<f64>, path: &str, upper_range: f64, caption: &str) {
    let root_area = BitMapBackend::new(&path, (1920, 1080)).into_drawing_area();
    root_area.fill(&WHITE).unwrap();
    let root_area = root_area.margin(40, 40, 40, 40);
    let mut ctx = ChartBuilder::on(&root_area)
        .set_label_area_size(LabelAreaPosition::Left, 40)
        .set_label_area_size(LabelAreaPosition::Bottom, 40)
        .caption(caption, ("Monospace", 30))
        .build_cartesian_2d((0..(y_data.len())), 0.0..upper_range)
        .unwrap();
    ctx.configure_mesh()
        .disable_x_mesh()
        .disable_y_mesh()
        .draw()
        .unwrap();
    ctx.draw_series({
        let mut area = AreaSeries::new(
            (0..).zip(y_data.iter()).map(|(x, y)| (x, *y)),
            0.0,
            &RED.mix(0.2),
        );
        area.border_style(&RED)
    })
    .unwrap();
    match root_area.present() {
        Ok(_) => {
            println!("Result has been saved to {}", &path);
        }
        Err(err) => {
            log_error(&format!("Unable to write result to file, please make sure 'plots' dir exists under current dir: {} with file {}", err.to_string(), &path));
        }
    }
}
