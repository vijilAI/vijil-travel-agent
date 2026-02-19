"""Smoke tests for travel agent imports and basic functionality."""

from genome_loader import GenomeLoader, GenomeMutation


def test_genome_loader_no_path():
    loader = GenomeLoader(None)
    genome = loader.get_current()
    assert isinstance(genome, GenomeMutation)
    assert genome.system_prompt is None


def test_genome_mutation_defaults():
    m = GenomeMutation()
    assert m.version == 0
    assert m.dome_config == {}
    assert m.system_prompt is None
