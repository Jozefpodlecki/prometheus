use plotters::prelude::*;
use plotters::coord::types::RangedCoordf64;

pub type XRange = RangedCoordf64;
pub type YRange = RangedCoordf64;
pub type CartesianCoord = Cartesian2d<XRange, YRange>;

pub type DrawingBackendType<'a> = BitMapBackend<'a>;
pub type ChartContextType<'a> = ChartContext<'a, DrawingBackendType<'a>, CartesianCoord>;